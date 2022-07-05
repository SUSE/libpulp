/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017-2021 SUSE Software Solutions GmbH
 *
 *  This file is part of libpulp.
 *
 *  libpulp is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  libpulp is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with libpulp.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "error_common.h"
#include "introspection.h"
#include "ptrace.h"
#include "ulp_common.h"

/** Set an amout of time to retry to read/write target process memory before
    giving up. The process could be being patched or analyzed by another ulp
    instance.  */
#define PTRACE_TIMEOUT 5

/*
 * Number of bytes that the kernel subtracts from the program counter,
 * when an ongoing syscall gets interrupted and must be restarted.
 */
#define RESTART_SYSCALL_SIZE 2

/* Translation Lookaside Buffer of size 1.  This is enough to reduce calls to
 * ptrace when calling read_byte because often it is used to read sequential
 * number of bytes.  */
static ElfW(Addr) tlb = 0;

/** @brief ulp ptrace wrapper
 *
 * The `ulp` tool uses ptrace to both update a process AND query for libraries
 * and patches installed in the process, and both things could be happening at
 * once. If this is the case, ptrace may sometimes fail with permissions or
 * busy errors. In this case, this wrapper tries ot ptrace a process multiple
 * times before concluding that it can't.
 *
 **/
static long
ulp_ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data)
{
  time_t t0, t1;
  long ret;

  t0 = time(NULL);
  do {
    errno = 0;

    ret = ptrace(request, pid, addr, data);

    switch (errno) {
      case EBUSY:
      case EPERM:
        usleep(10000);
        break;

      case EIO:
      case EFAULT:
      case EINVAL:
      case ESRCH:
      case 0:
        return ret;
        break;
    }
    t1 = time(NULL);
  }
  while (t1 - t0 < PTRACE_TIMEOUT);

  return ret;
}

/** This file should not call ptrace directly anymore.  */
#pragma GCC poison ptrace

int
write_bytes(const void *buf, size_t n, int pid, Elf64_Addr addr)
{
  /* Invalidate tlb because we are commiting changes to memory.  */
  tlb = 0;
  unsigned long *lbuf = (unsigned long *)buf;
  size_t num_longs = n / sizeof(long);
  size_t num_remainders = n % sizeof(long);

  while (num_longs-- > 0) {
    ulp_ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)*lbuf++);
    if (errno) {
      DEBUG("Unable to write long at address %lx: %s\n", addr,
            strerror(errno));
      return 1;
    }
    addr += sizeof(long);
  }

  if (num_remainders > 0) {
    unsigned long remainder;
    remainder = ulp_ptrace(PTRACE_PEEKDATA, pid, (void *)addr, 0);
    if (errno) {
      DEBUG("unable to read byte before writing: %s\n", strerror(errno));
      return 1;
    }
    memcpy(&remainder, lbuf, num_remainders);
    ulp_ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)remainder);
    if (errno) {
      DEBUG("Unable to write long at address %lx: %s\n", addr,
            strerror(errno));
      return 1;
    }
  }
  return 0;
}

/*
 * Writes the string pointed to by BUFFER into the address space of PID at
 * ADDR. At most LENGTH bytes are written. If BUFFER is not null-terminated,
 * the destination string will have its last byte converted into null.
 *
 * Returns 0 if the operation succeeds; 1 otherwise.
 */
int
write_string(const char *buffer, int pid, Elf64_Addr addr, int size)
{
  size_t len = strlen(buffer);

  if (len > (unsigned)size) {
    len = size;
  }

  /* Invalidate tlb because we are commiting changes to memory.  */
  tlb = 0;

  return write_bytes(buffer, len, pid, addr);
}

static int
ptrace_peekdata(long *value, int pid, Elf64_Addr addr)
{
  errno = 0;
  *value = ulp_ptrace(PTRACE_PEEKDATA, pid, (void *)addr, 0);
  if (errno) {
    DEBUG("unable to read byte: %s\n", strerror(errno));
    return 1;
  }

  return 0;
}

/* Read the content of size `long`.  This should increase the ptrace bandwidth
   when compared to read_bytes.  */
int
read_long(long *word, int pid, Elf64_Addr addr)
{
  long value;
  int ret = ptrace_peekdata(&value, pid, addr);
  if (!ret) {
    memcpy(word, &value, sizeof(long));
  }

  return ret;
}

int
read_byte(char *byte, int pid, Elf64_Addr addr)
{
  /* Hold last ptrace_peekdata.  */
  static char tlb_value[sizeof(long)];

  long value;
  int ret;

  /* In case the requested data is cached, access the cache
   * and return the value there.
   */
  if (tlb <= addr && addr < tlb + sizeof(long)) {
    *byte = tlb_value[addr - tlb];
    return 0;
  }

  ret = ptrace_peekdata(&value, pid, addr);
  if (!ret) {
    /* Update the tlb structure with the last ptrace_peekdata.  */
    tlb = addr;
    memcpy(tlb_value, &value, sizeof(long));
    *byte = tlb_value[0];
  }

  return ret;
}

int
read_memory(char *byte, size_t len, int pid, Elf64_Addr addr)
{
  size_t i;
  size_t len_word = len / sizeof(long);
  size_t len_remaining = len % sizeof(long);

  long *word = (long *)byte;

  if (attach(pid)) {
    DEBUG("unable to attach to %d to read data.\n", pid);
    return 1;
  };

  /* Read as much as we can using longs, since it has larger bandwith when
     compared to bytes.  */
  for (i = 0; i < len_word; i++) {
    if (read_long(&word[i], pid, addr + i * sizeof(long)))
      return 1;
  }

  /* In case the size of long does not divide len, then we must also read the
     remainder.  */
  byte = byte + len_word * sizeof(long);
  addr = addr + len_word * sizeof(long);
  for (i = 0; i < len_remaining; i++) {
    if (read_byte(&byte[i], pid, addr + i))
      return 1;
  }

  if (detach(pid)) {
    DEBUG("unable to detach from %d after reading data.\n", pid);
    return 1;
  };

  return 0;
}

int
read_string(char **buffer, int pid, Elf64_Addr addr)
{
  int i = 0;
  char *string;
  int buffer_len;

  if (attach(pid)) {
    DEBUG("unable to attach to %d to read string.", pid);
    return 1;
  }

  buffer_len = 32;
  string = (char *)malloc(buffer_len);

  do {
    /* Grow the buffer if the string won't fit in it.  */
    if (i >= buffer_len) {
      buffer_len *= 2;
      string = realloc(string, buffer_len);
    }

    if (read_byte(&string[i], pid, addr + i)) {
      WARN("Unable to read string at address 0x%lx", addr + i);
      free(string);
      return 1;
    }
  }
  while (string[i++] != '\0');

  if (detach(pid)) {
    DEBUG("unable to detach from %d after reading string.", pid);
    return 1;
  };

  *buffer = string;
  return 0;
}

int
attach(int pid)
{
  int status;

  if (ulp_ptrace(PTRACE_ATTACH, pid, NULL, NULL)) {
    DEBUG("PTRACE_ATTACH error: %s.\n", strerror(errno));
    return 1;
  }

  while (1) {
    if (waitpid(pid, &status, __WALL) == -1) {
      DEBUG("waitpid error (pid %d): %s.\n", pid, strerror(errno));
      return 1;
    }

    if (WIFSTOPPED(status)) {
      /* Everything went as expected.  */
      return 0;
    }

    if (WIFEXITED(status)) {
      WARN("Process %d exited while waiting for stop signal.", pid);
      return 1;
    }

    if (WIFSIGNALED(status)) {
      WARN("Process %d terminated by a signal while waiting for stop signal.",
           pid);
      return 1;
    }
  }
  __builtin_unreachable();
}

int
detach(int pid)
{
  if (ulp_ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
    DEBUG("PTRACE_DETACH error: %s.\n", strerror(errno));
    return 1;
  }

  /* Invalidate tlb because we are returning control to the process.  */
  tlb = 0;
  return 0;
}

int
get_regs(int pid, struct user_regs_struct *regs)
{
  if (ulp_ptrace(PTRACE_GETREGS, pid, NULL, regs)) {
    DEBUG("PTRACE_GETREGS error: %s.\n", strerror(errno));
    return 1;
  }
  return 0;
}

int
set_regs(int pid, struct user_regs_struct *regs)
{
  if (ulp_ptrace(PTRACE_SETREGS, pid, NULL, regs)) {
    DEBUG("PTRACE_SETREGS error: %s.\n", strerror(errno));
    return 1;
  }
  return 0;
}

/** Timeout for run_and_redirect function.  Set default to 10s.  */
static long rr_timeout = 10;

/** @brief Set timeout timer on run_and_redirect function
 *
 * If for some reason libpulp.so deadlocks when livepatching, the only
 * way we can 'detect' it is by using a timer. This function let the
 * user control this timer
 * timer
 *
 * @param t   New timeout value.
 *
 **/
void
set_run_and_redirect_timeout(long t)
{
  rr_timeout = t;
}

int
run_and_redirect(int pid, struct user_regs_struct *regs, ElfW(Addr) routine)
{
  int status;
  time_t t0, t1;
  bool success = false;
  long timeout = rr_timeout;

  /*
   * After an ongoing syscall gets interrupted (for instance by
   * PTRACE_ATTACH), but before returning control to userspace (with
   * PTRACE_CONT), the kernel subtracts some bytes from the program
   * counter, so that the syscall instruction gets re-executed.
   *
   * Libpulp itself does not make syscalls, still it might be affected
   * by this syscall restarting mechanism, because it modifies
   * (between PTRACE_ATTACH and PTRACE_CONT) the program counter of
   * selected threads so that they perform live patching operations.
   *
   * Thus, live patching routines from libpulp (see ulp_interface.S),
   * must work when executed from their normal start address, as well
   * as from a few bytes before it. As such, they start with a few
   * nops, which are skipped below.
   */
  regs->rip = routine + RESTART_SYSCALL_SIZE;

  /*
   * Even though libpulp does not register signal handlers with the
   * kernel, it uses ptrace to hijack all threads in a process, then
   * diverts the execution of one of these threads to apply live
   * patches and check patching status. Thus, live patching happens
   * from a context similar to that of signal handlers, therefore, it
   * must follow the rules of the ABI related to signal handlers, more
   * specifically, it cannot touch the red zone.
   *
   * With regular signal handlers, the Linux kernel adjusts the stack
   * pointer before transferring control to registered handlers. Since
   * libpulp uses ptrace and thread hijacking, instead of regular
   * handler registering, it cannot rely on this kernel feature, so it
   * must adjust the stack on its own.
   */
  regs->rsp -= RED_ZONE_LEN;

  /*
   * The ABI for AMD64 requires that the stack pointer be aligned on a
   * 16, 32, or 64 byte boundary before function calls. In its words:
   *
   *   The end of the input argument area shall be aligned on a 16 (32
   *   or 64, if __m256 or __m512 is passed on stack) byte boundary.
   *   In other words, the value (%rsp + 8) is always a multiple of 16
   *   (32 or 64) when control is transferred to the function entry
   *   point. The stack pointer, %rsp, always points to the end of the
   *   latest allocated stack frame.
   *
   * Taking a conservative approach, libpulp always aligns on the
   * highest boundary, before transfering control to the live patching
   * routines in ulp_interface.S.
   */
  regs->rsp &= 0xFFFFFFFFFFFFFFC0;

  if (ulp_ptrace(PTRACE_SETREGS, pid, NULL, regs)) {
    WARN("PTRACE_SETREGS error (pid %d).\n", pid);
    return ETARGETHOOK;
  }

  if (ulp_ptrace(PTRACE_CONT, pid, NULL, NULL)) {
    WARN("PTRACE_CONT error (pid %d).\n", pid);
    return ETARGETHOOK;
  }

  t0 = time(NULL);
  do {
    pid_t ret;

    usleep(1000);
    /* Query on pid to check if the process has stopped.  */
    ret = waitpid(pid, &status, WNOHANG | WSTOPPED);

    if (ret == -1) {
      /* waitpid returned an error state.  */
      WARN("waitpid error (pid %d).\n", pid);
      return EUNKNOWN;
    }
    else if (ret == pid) {
      /* Expected correct value: the process state changed in process with
       * pid=pid*/

      if (WIFEXITED(status) || WCOREDUMP(status)) {
        /* If the process exited for some reason, we can not continue.  */
        WARN("%d failed %s.\n", pid, strsignal(WEXITSTATUS(status)));
        return EUNKNOWN;
      }

      /* Check if the process indeed stopped. Else we have to continue trying.
       */
      if (WIFSTOPPED(status)) {
        success = true;
        break;
      }
    }
    else if (ret > 0) {
      /* Unexpected process stopped?  */
      DEBUG(
          "waitpid: state changed on unexpected process: expected %d, got %d",
          pid, ret);
    }
    t1 = time(NULL);
  }
  while (t1 - t0 < timeout);

  if (!success) {
    return ETIME;
  }

  /* Read the full context to learn about return values. */
  if (ulp_ptrace(PTRACE_GETREGS, pid, NULL, regs)) {
    WARN("PTRACE_GETREGS error (pid %d).\n", pid);
    return -1;
  }

  return 0;
}
