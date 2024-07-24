/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2020-2021 SUSE Software Solutions GmbH
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

/* Use some live-patchable library to apply live patches. */
#include <libblocked.h>

/* Iterate for a while to let the trigger tool apply a live patch. */
#define LOOPS 1000000000

int
main(void)
{
  volatile long int counter = LOOPS;
  volatile long int result1;
  volatile long int result2;
  volatile long int result3;

  /* Signal readiness. */
  printf("Waiting for input.\n");

  /*
   * Play with double words in the red zone:
   *   - Initialize double words in the red zone to zero;
   *   - Iterate LOOPS times, incrementing them;
   *   - Output them to result<N>.
   */
  /* clang-format off */
  asm volatile (
#if defined(__x86_64__)
    "movq $0, -0x08(%%rsp)\n"
    "movq $0, -0x78(%%rsp)\n"
    "movq $0, -0x80(%%rsp)\n"
    "loop:\n"
    "addq $1, -0x08(%%rsp)\n"
    "addq $1, -0x78(%%rsp)\n"
    "addq $1, -0x80(%%rsp)\n"
    "subq $1, %3\n"
    "cmp $0, %3\n"
    "jne loop\n"
    "movq -0x08(%%rsp), %0\n"
    "movq -0x78(%%rsp), %1\n"
    "movq -0x80(%%rsp), %2\n"
#elif defined(__powerpc64__)
    "li %%r10, 0\n"
    "stw %%r10, -0x08(%%r1)\n"
    "stw %%r10, -0x78(%%r1)\n"
    "stw %%r10, -0x80(%%r1)\n"
    "loop:\n"
    "li %%r10, 1\n"
    "lwa %%r11, -0x08(%%r1)\n"
    "add %%r11, %%r11, %%r10\n"
    "stw %%r11, -0x08(%%r1)\n"
    "lwa %%r11, -0x78(%%r1)\n"
    "add %%r11, %%r11, %%r10\n"
    "stw %%r11, -0x78(%%r1)\n"
    "lwa %%r11, -0x80(%%r1)\n"
    "add %%r11, %%r11, %%r10\n"
    "stw %%r11, -0x80(%%r1)\n"
    "addi %3, %3, -1\n"
    "cmpdi %%cr0, %3, 0\n"
    "bne %%cr0, loop\n"
    "lwz %0, -0x08(%%r1)\n"
    "lwz %1, -0x78(%%r1)\n"
    "lwz %2, -0x80(%%r1)\n"
#endif
    : "=r"(result1), "=r"(result2), "=r"(result3), "+r"(counter)
  );
  /* clang-format on */

  if (result1 == LOOPS && result2 == LOOPS && result3 == LOOPS)
    return 0;

  hello();

  printf("Got %ld, %ld, and %ld, when all values expected to be %ld\n",
         result1, result2, result3, (long int)LOOPS);
  return 1;
}
