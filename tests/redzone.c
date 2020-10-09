/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2020 SUSE Software Solutions GmbH
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
main (void)
{
  long int counter = LOOPS;
  long int result;

  /* Signal readiness. */
  printf ("Waiting for input.\n");

  /*
   * Play with a double word in the red zone:
   *   - Initialize a double word in the red zone to zero;
   *   - Iterate LOOPS times, incrementing it;
   *   - Output it to result.
   */
  asm volatile (
    "movq $0, -0x8(%%rsp)\n"
    "loop:\n"
    "addq $1, -0x8(%%rsp)\n"
    "subq $1, %1\n"
    "cmp $0, %1\n"
    "jne loop\n"
    "movq -0x8(%%rsp), %0"
    : "=r"(result), "+r"(counter)
  );

  if (result == (LOOPS))
    return 0;

  hello ();

  printf ("Got %ld, expected %ld\n", result, (long int) LOOPS);
  return 1;
}
