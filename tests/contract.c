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
#include <stdio.h>

#include <libcontract.h>

int
main(void)
{
  char buffer[128];

  /* Signal readiness. */
  printf("Waiting for input.\n");

  /* Loop waiting for input and calling function(). */
  while (1) {
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
      if (errno) {
        perror("contract");
        return 1;
      }
      printf("Reached the end of file; quitting.\n");
      return 0;
    }
    fna();
    fnb();
  }
}
