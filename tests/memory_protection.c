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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/mman.h>

#include <libaddress.h>

/* Do not optimize, otherwise the read/write sequence go away. */
#pragma GCC push_options
#pragma GCC optimize("O0")

void
disturb_memory(void *addr)
{
  int word;

  word = *((int *)addr);
  *((int *)addr) = word;
}

/* Restore optimization level. */
#pragma GCC pop_options

int
main(void)
{
  char buffer[128];
  int retcode;
  unsigned long page_size;
  uintptr_t page_mask;
  void *page_addr;
  void *addr;

  page_size = getpagesize();
  page_mask = ~(page_size - 1);

  /* Get an address from the library. */
  addr = get_address();

  /* Enable writes to the code area. */
  page_addr = (void *)((uintptr_t)addr & page_mask);
  retcode = mprotect(page_addr, 1, PROT_READ | PROT_WRITE | PROT_EXEC);
  if (retcode) {
    perror("mprotect");
    return 1;
  }

  /* Loop waiting for any input. */
  printf("Waiting for input.\n");
  while (1) {
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
      if (errno) {
        perror("memory_protection");
        return 1;
      }
      printf("Reached the end of file; quitting.\n");
      return 0;
    }

    /*
     * If applying a live patch fails to restore the write permission set
     * above, writing to addr (with disturb_memory(addr)) will cause a
     * segmentation fault.
     */
    disturb_memory(addr);

    /* Use the library. */
    if (get_address() == NULL)
      printf("NULL\n");
    else
      printf("Non-NULL\n");
  }

  return 1;
}
