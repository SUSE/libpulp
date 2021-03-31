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
#include <stdlib.h>

enum
{
  TYPE_A,
  TYPE_B
};

struct message
{
  int type;
  int data_a;
  double data_b;
};

void
wait_input(void)
{
  char buffer[128];

  if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
    if (errno) {
      perror("contract");
      exit(1);
    }
    printf("Reached the end of file; quitting.\n");
    exit(0);
  }
}

void
print(struct message *message)
{
  switch (message->type) {
    case TYPE_A:
      printf("TYPE A data %d\n", message->data_a);
      break;
    case TYPE_B:
      printf("TYPE B data %f\n", message->data_b);
      break;
    default:
      printf("Invalid type.\n");
  }
}

void
fna(void)
{
  struct message message;

  message.type = TYPE_A;
  message.data_a = 128;

  wait_input();

  print(&message);
}

void
fnb(void)
{
  struct message message;

  message.type = TYPE_B;
  message.data_b = 256;

  wait_input();

  print(&message);
}
