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

#include <argp.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
#include <unistd.h>

#include "arguments.h"
#include "config.h"
#include "introspection.h"
#include "messages.h"
#include "msg_queue.h"
#include "ulp_common.h"

static Elf64_Addr
get_msgq_address(const struct ulp_process *p)
{
  struct ulp_dynobj *dyn;
  Elf64_Addr msgq_addr = 0;

  for (dyn = p->dynobj_libpulp; dyn != NULL; dyn = dyn->next) {
    if (dyn->msg_queue) {
      msgq_addr = dyn->msg_queue;
      break;
    }
  }

  return msgq_addr;
}

static void
msgq_print(struct msg_queue *msg_queue)
{
  int bottom = msg_queue->bottom;
  int distance = msg_queue->distance;

  while (distance > 0) {
    putchar(msg_queue->buffer[bottom]);
    bottom = (bottom + 1) % MSGQ_BUFFER_MAX;
    distance--;
  }
}

static void
msgq_debug(struct msg_queue *msg_queue)
{
  int i;
  for (i = 0; i < MSGQ_BUFFER_MAX; i++) {
    if (msg_queue->buffer[i] == '\0')
      putchar('.');
    else
      putchar(msg_queue->buffer[i]);
  }
  putchar('\n');

  for (i = 0; i < MSGQ_BUFFER_MAX; i++) {
    if (msg_queue->bottom == i)
      putchar('B');
    else if (msg_queue->top == i)
      putchar('T');
    else
      putchar(' ');
  }
  putchar('\n');
}

static int
print_message_buffer(const struct ulp_process *p, bool debug)
{
  static struct msg_queue msg_queue;
  int ret;

  Elf64_Addr msgq_addr = get_msgq_address(p);

  memset(&msg_queue, 0, sizeof(struct msg_queue));

  if (!msgq_addr) {
    WARN("could not find libpulp.so message queue in process %d.", p->pid);
    return 1;
  }

  ret = read_memory((void *)&msg_queue, sizeof(struct msg_queue), p->pid,
                    msgq_addr);
  if (ret > 0) {
    WARN("could not read libpulp.so message queue in process %d.", p->pid);
    return 1;
  }

  if (debug)
    msgq_debug(&msg_queue);
  else
    msgq_print(&msg_queue);

  return ret;
}

int
run_messages(struct arguments *arguments)
{
  int ret = 0;
  struct ulp_process *target = calloc(1, sizeof(struct ulp_process));

  /* Set the verbosity level in the common introspection infrastructure. */
  ulp_verbose = arguments->verbose;
  ulp_quiet = arguments->quiet;

  target->pid = arguments->pid;
  ret = initialize_data_structures(target);
  if (ret) {
    WARN("error gathering target process information.");
    ret = 1;
    goto ulp_process_clean;
  }

  ret = print_message_buffer(target, false);
  if (ret > 0) {
    WARN("message queue reading failed.");
    ret = 1;
    goto ulp_process_clean;
  }

ulp_process_clean:
  release_ulp_process(target);
  return ret;
}
