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
#include <unistd.h>

#include "introspection.h"
#include "ptrace.h"
#include "ulp_common.h"

/*
 * Number of bytes that the kernel subtracts from the program counter,
 * when an ongoing syscall gets interrupted and must be restarted.
 */
#define RESTART_SYSCALL_SIZE 2

/* Memory read/write helper functions */
int
write_byte(char byte, int pid, Elf64_Addr addr)
{
  Elf64_Addr value;

  errno = 0;
  value = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
  if (errno) {
    DEBUG("unable to read byte before writing: %s\n", strerror(errno));
    return 1;
  }
  memset(&value, byte, 1);
  ptrace(PTRACE_POKEDATA, pid, addr, value);
  if (errno) {
    DEBUG("Unable to write byte: %s\n", strerror(errno));
    return 1;
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
write_string(char *buffer, int pid, Elf64_Addr addr, int length)
{
  int i;

  for (i = 0; i < length && buffer[i] != '\0'; i++) {
    if (write_byte(buffer[i], pid, addr + i))
      return 1;
  }

  if (i < length)
    if (write_byte('\0', pid, addr + i))
      return 1;

  return 0;
}

int
read_byte(char *byte, int pid, Elf64_Addr addr)
{
  Elf64_Addr value;

  errno = 0;
  value = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
  if (errno) {
    DEBUG("unable to read byte: %s\n", strerror(errno));
    return 1;
  }
  *byte = value & 0xff;

  return 0;
}

int
read_memory(char *byte, size_t len, int pid, Elf64_Addr addr)
{
  size_t i;

  if (attach(pid)) {
    DEBUG("unable to attach to %d to read data.\n", pid);
    return 1;
  };

  for (i = 0; i < len; i++)
    if (read_byte(byte + i, pid, addr + i))
      return 1;

  if (detach(pid)) {
    DEBUG("unable to detach from %d after reading data.\n", pid);
    return 1;
  };

  return 0;
}

int
read_string(char **buffer, int pid, Elf64_Addr addr)
{
  int len = 0, i;
  char byte;

  if (attach(pid)) {
    DEBUG("unable to attach to %d to read string.", pid);
    return 1;
  }

  while (!read_byte(&byte, pid, addr + len) && byte)
    len++;

  *buffer = malloc(len + 1);
  if (!buffer) {
    DEBUG("unable to allocate memory (%d bytes).", len);
    return 1;
  }

  for (i = 0; i < len; i++) {
    if (read_byte((*buffer + i), pid, addr + i)) {
      return 1;
    }
  }
  *(*buffer + i) = '\0';

  if (detach(pid)) {
    DEBUG("unable to detach from %d after reading string.", pid);
    return 1;
  };

  return 0;
}

int
attach(int pid)
{
  int status;

  if (ptrace(PTRACE_ATTACH, pid, NULL, NULL)) {
    DEBUG("PTRACE_ATTACH error: %s.\n", strerror(errno));
    return 1;
  }

  usleep(1000);
  if (waitpid(-1, &status, __WALL) == -1) {
    DEBUG("waitpid error (pid %d): %s.\n", pid, strerror(errno));
    return 1;
  }

  return 0;
}

int
detach(int pid)
{
  if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
    DEBUG("PTRACE_DETACH error: %s.\n", strerror(errno));
    return 1;
  }
  return 0;
}

int
get_regs(int pid, struct user_regs_struct *regs)
{
  if (ptrace(PTRACE_GETREGS, pid, NULL, regs)) {
    DEBUG("PTRACE_GETREGS error: %s.\n", strerror(errno));
    return 1;
  }
  return 0;
}

int
set_regs(int pid, struct user_regs_struct *regs)
{
  if (ptrace(PTRACE_SETREGS, pid, NULL, regs)) {
    DEBUG("PTRACE_SETREGS error: %s.\n", strerror(errno));
    return 1;
  }
  return 0;
}

int
run_and_redirect(int pid, struct user_regs_struct *regs, ElfW(Addr) routine)
{
  int status;

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

  if (ptrace(PTRACE_SETREGS, pid, NULL, regs)) {
    WARN("PTRACE_SETREGS error (pid %d).\n", pid);
    return 1;
  }

  if (ptrace(PTRACE_CONT, pid, NULL, NULL)) {
    WARN("PTRACE_CONT error (pid %d).\n", pid);
    return 1;
  }

  usleep(1000);
  if (waitpid(-1, &status, __WALL) == -1) {
    WARN("waitpid error (pid %d).\n", pid);
    return -1;
  }

  if (WIFEXITED(status) || WCOREDUMP(status)) {
    WARN("%d failed %s.\n", pid, strsignal(WEXITSTATUS(status)));
    return -1;
  }

  if (!WIFSTOPPED(status)) {
    WARN("Target %d did not stop.\n", pid);
    return -1;
  }

  /* Read the full context to learn about return values. */
  if (ptrace(PTRACE_GETREGS, pid, NULL, regs)) {
    WARN("PTRACE_GETREGS error (pid %d).\n", pid);
    return -1;
  }

  return 0;
}
