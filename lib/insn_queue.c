/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2021 SUSE Software Solutions GmbH
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

#include "insn_queue.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "error.h"
#include "ulp_common.h"

/** Global instruction queue object.  */
insn_queue_t __ulp_insn_queue = { .version = INSNQ_CURR_VERSION };

static int
align_to(int val, int bytes)
{
  int mask = bytes - 1;
  return (val + mask) & (~mask);
}

/** @brief Get memory area to write an instruction to in the queue.
 *
 * This function will retrieve an area of memory in the queue object in which
 * an instruction of size `msg_size` can be writen to. The instruction is
 * appended to the end of the queue, and depending of the queue attribute
 * `discard_old_content` it may return NULL if there is pending operations in
 * the queue, or overwrite the instruction that is on the begining of the
 * queue. In case the instruction do not fit in the queue, NULL is returned.
 *
 * @param queue     The instruction queue object.
 * @param msg_size  Size of instruction to allocate area to.
 *
 * @return          Valid pointer to write to in success, NULL otherwise.

  */
void *
insnq_get_writable_area(struct insn_queue *queue, size_t msg_size)
{
  /* Write the msg_queue values in variables for briefness.  */
  int num_insns = queue->num_insns;
  int size = queue->size;
  char *buffer = queue->buffer;

  /* In case the message is empty or it is too large for the buffer, don't
   * bother even trying to insert it.  */
  if (msg_size == 0)
    return NULL;

  /* In case the instruction won't fit the queue, then quickly return with
     NULL as answer.  */
  if (msg_size + size > INSN_BUFFER_MAX) {
    return NULL;
  }

  /* Reserve area for write.  This breaks strict aliasing rules, so this file
     must be compiled with -fno-strict-aliasing.  */
  void *ret = &buffer[size];

  /* Update number of bytes.  */
  size += msg_size;
  num_insns++;

  /* Commit back to original object.  */

  queue->num_insns = num_insns;
  queue->size = size;

  return ret;
}

/** @brief Insert print instruction into the queue.
 *
 * @param queue    The instruction queue object.
 * @param string   String to print.
 */
ulp_error_t
insnq_insert_print(const char *string)
{
  insn_queue_t *queue = &__ulp_insn_queue;

  int string_size = strlen(string) + 1;
  int insn_size = align_to(sizeof(struct ulp_insn_print) + string_size, 4);
  struct ulp_insn_print *insn = insnq_get_writable_area(queue, insn_size);

  if (insn == NULL) {
    set_libpulp_error_state(EINSNQ);
    return EINSNQ;
  }

  insn->base.type = ULP_INSN_PRINT;
  insn->base.size = insn_size;
  memcpy(insn->bytes, string, string_size);

  return ENONE;
}

/** @brief Insert write instruction into the queue.
 *
 * @param queue    The instruction queue object.
 * @param addr     Address to patch.
 * @param n        Number of bytes to patch.
 * @param bytes    Bytes to patch with.
 */
ulp_error_t
insnq_insert_write(void *addr, int n, const void *bytes)
{
  insn_queue_t *queue = &__ulp_insn_queue;

  int insn_size = align_to(sizeof(struct ulp_insn_write) + n, 8);
  struct ulp_insn_write *insn = insnq_get_writable_area(queue, insn_size);

  if (insn == NULL) {
    set_libpulp_error_state(EINSNQ);
    return EINSNQ;
  }

  insn->base.type = ULP_INSN_WRITE;
  insn->base.size = insn_size;
  insn->n = n;
  insn->address = (uintptr_t)addr;
  memcpy(insn->bytes, bytes, n);

  return ENONE;
}

/** @brief Ensure that the instruction queue is empty.
 *
 * When a livepatch is triggered, the instruction queue must be empty in order
 * to safely insert instructions on it.  Otherwise, this means something bad
 * occured on ulp side which prevented the queue to be updated after the insns
 * were executed.
 *
 * This function will block livepatching if not empty.
 *
 * @return 0 if success, anything else if not empty
 *
 */
int
insnq_ensure_emptiness(void)
{
  insn_queue_t *queue = &__ulp_insn_queue;

  if (queue->num_insns > 0 || queue->size > 0) {
    WARN("WARN: instruction queue not empty. This is an indication that "
         "something went wrong on ulp side.");

    set_libpulp_error_state(EINSNQ);
    return 1;
  }

  return 0;
}


/*
 * Read one line from FD into BUF, which must be pre-allocated and large
 * enough to hold LEN characteres. The offset into FD is advanced by the
 * amount of bytes read.
 *
 * @return  -1 on error, 0 on End-of-file, or the amount of bytes read.
 */
static int
read_line(int fd, char *buf, size_t len)
{
  char *ptr;
  int retcode;
  size_t offset;

  /* Read one byte at a time, until a newline is found. */
  offset = 0;
  while (offset < len) {
    ptr = buf + offset;

    /* Read one byte. */
    retcode = read(fd, ptr, 1);

    /* Error with read syscall. */
    if (retcode == -1) {
      if (errno == EINTR || errno == EAGAIN)
        continue;
      else
        return -1;
    }

    /* Stop at EOF or EOL. */
    if (retcode == 0 || *ptr == '\n') {
      return offset;
    }

    offset++; /* Reading one byte at a time. */
  }

  /* EOL not found. */
  return -1;
}

/* @brief Retrieves the memory protection bits of the page containing ADDR.
 *
 * @param addr    Address of the page.
 * @return        If errors ocurred, return -1.
 */
static int __attribute((unused))
memory_protection_get(uintptr_t addr)
{
  char line[LINE_MAX];
  char *str;
  char *end;
  int fd;
  int result;
  int retcode;
  uintptr_t addr1;
  uintptr_t addr2;

  fd = open("/proc/self/maps", O_RDONLY);
  if (fd == -1)
    return -1;

  /* Iterate over /proc/self/maps lines. */
  result = -1;
  for (;;) {

    /* Read one line. */
    retcode = read_line(fd, line, LINE_MAX);
    if (retcode <= 0)
      break;

    /* Parse the address range in the current line. */
    str = line;
    addr1 = strtoul(str, &end, 16);
    str = end + 1; /* Skip the dash used in the range output. */
    addr2 = strtoul(str, &end, 16);

    /* Skip line if target address not within range. */
    if (addr < addr1 || addr >= addr2)
      continue;

    /* Otherwise, parse the memory protection bits. */
    result = 0;
    if (*(end + 1) == 'r')
      result |= PROT_READ;
    if (*(end + 2) == 'w')
      result |= PROT_WRITE;
    if (*(end + 3) == 'x')
      result |= PROT_EXEC;
    break;
  }

  close(fd);
  return result;
}

/* When we are testing insnq there are some functions we do not want in the
   compilation unit.  */
#ifndef DISABLE_INSNQ_FUNCS_FOR_TESTING

/** @brief Interpret WRITE instruction.
 *
 * @param insn    Instruction to interpet. Must be a WRITE instruction.
 *
 * @return        Size of interpreted instruction.
 */
int
insn_interpret_write(struct ulp_insn *insn)
{
  struct ulp_insn_write *winsn = (struct ulp_insn_write *)insn;

  uintptr_t page_mask, page_size;

  page_size = getpagesize();
  page_mask = ~(page_size - 1);

  uintptr_t page1 = winsn->address & page_mask;
  uintptr_t pagen = (winsn->address + winsn->n) & page_mask;

  int num_pages = 1 + (pagen - page1) / page_size;

  int prot[num_pages];

  for (int i = 0; i < num_pages; i++) {
    uintptr_t page = page1 + i * page_size;

    /* Make sure we always get the one with page size.  */
    libpulp_assert(page == (page & page_mask));

    prot[i] = memory_protection_get(page);

    if (prot[i] == -1) {
      WARN("Memory protection get error (%d page)", i);
      return errno;
    }
  }

  for (int i = 0; i < num_pages; i++) {
    uintptr_t page = page1 + i * page_size;
    if (mprotect((void *)page, page_size, prot[i] | PROT_WRITE)) {
      WARN("Memory protection set error (%d page)", i);
      return errno;
    }
  }

  memcpy((void *)winsn->address, winsn->bytes, winsn->n);

  /* Make sure we wrote that.  */
  if (memcmp((void *)winsn->address, winsn->bytes, winsn->n) != 0) {
    WARN("Failed to write at address 0x%lx", winsn->address);
  }

  for (int i = 0; i < num_pages; i++) {
    uintptr_t page = page1 + i * page_size;
    if (mprotect((void *)page, page_size, prot[i])) {
      WARN("Memory protection set error (%d page)", i);
      return errno;
    }
  }

  return insn->size;
}

#endif //DISABLE_INSNQ_FUNCS_FOR_TESTING

/** @brief Process global instruction queue.
  *
  * Processes the global instruction queue that should be sent to the `ulp`
  * command, but we may need to process this queue in the process side if we
  * are debugging libpulp (e.g. patch triggered from gdb interface).
  */
int
insnq_interpret_from_lib(void)
{
  /* Interpret global queue.  */
  struct insn_queue *queue = &__ulp_insn_queue;
  int ret = insnq_interpret(queue);

  /* Clean up the queue.  */
  memset(queue->buffer, 0, INSN_BUFFER_MAX);
  queue->num_insns = 0;
  queue->size = 0;

  return ret;
}
