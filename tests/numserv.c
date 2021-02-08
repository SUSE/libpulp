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
#include <string.h>

#include <dozens.h>
#include <hundreds.h>

int
main(void)
{
  char input[64];

  printf("Waiting for input.\n");
  while (1) {
    if (scanf("%s", input) == EOF) {
      if (errno) {
        perror("numserv");
        return 1;
      }
      printf("Reached the end of file; quitting.\n");
      return 0;
    }
    if (strncmp(input, "dozen", strlen("dozen")) == 0)
      printf("%d\n", dozen());
    if (strncmp(input, "hundred", strlen("hundred")) == 0)
      printf("%d\n", hundred());
    if (strncmp(input, "quit", strlen("quit")) == 0) {
      printf("Quitting.\n");
      return 0;
    }
  }

  return 1;
}
