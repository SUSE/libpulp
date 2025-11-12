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
#include <argp.h>

#include "arguments.h"
#include "config.h"
#include "introspection.h"
#include "messages.h"
#include "msg_queue.h"
#include "ulp_common.h"

static Elf64_Addr
get_msgq_address(const struct ulp_process *p, bool *old)
{
  struct ulp_dynobj *dyn;
  Elf64_Addr msgq_addr = 0;

  for (dyn = p->dynobj_libpulp; dyn != NULL; dyn = dyn->next) {

    /* Try the old queue first.  */
    if (dyn->msg_queue_old) {
      *old = true;
      msgq_addr = dyn->msg_queue_old;
    }

    if (dyn->msg_queue) {
      *old = false;
      msgq_addr = dyn->msg_queue;
      break;
    }
  }

  return msgq_addr;
}

static void
msgq_print(int size, int bottom, int distance, const char *buffer)
{
  while (distance > 0) {
    putchar(buffer[bottom]);
    bottom = (bottom + 1) % size;
    distance--;
  }
}

static void
msgq_debug(int size, int bottom, int top, const char *buffer)
{
  int i;
  for (i = 0; i < size; i++) {
    if (buffer[i] == '\0')
      putchar('.');
    else
      putchar(buffer[i]);
  }
  putchar('\n');

  for (i = 0; i < size; i++) {
    if (bottom == i)
      putchar('B');
    else if (top == i)
      putchar('T');
    else
      putchar(' ');
  }
  putchar('\n');
}

static int
print_message_buffer_new(int pid, Elf64_Addr msgq_addr, bool debug)
{
  static struct msg_queue msg_queue;
  int ret;

  memset(&msg_queue, 0, sizeof(msg_queue));

  if (attach(pid)) {
    DEBUG("unable to attach to %d to read string.", pid);
    return 1;
  }

  /* Read the first bytes without the buffer to determine the size.  */
  ret = read_memory(&msg_queue, offsetof(struct msg_queue, buffer), pid,
                    msgq_addr);

  if (ret > 0) {
    WARN("could not read libpulp.so message queue in process %d.", pid);
    return 1;
  }

  if (msg_queue.size > MSGQ_BUFFER_MAX) {
    WARN("libpulp.so message queue size is not valid.", pid);
    msg_queue.size = MSGQ_BUFFER_MAX;
  }

  /* Read the buffer now.  */
  ret = read_memory(msg_queue.buffer, msg_queue.size, pid,
                    msgq_addr + offsetof(struct msg_queue, buffer));

  if (detach(pid)) {
    DEBUG("unable to detach from %d.", pid);
    return 1;
  }

  if (ret > 0) {
    WARN("could not read libpulp.so message queue in process %d.", pid);
    return 1;
  }

  int size = msg_queue.size;
  int bottom = msg_queue.bottom;
  int top = msg_queue.top;
  int distance = msg_queue.distance;
  const char *buffer = msg_queue.buffer;

  if (debug)
    msgq_debug(size, bottom, top, buffer);
  else
    msgq_print(size, bottom, distance, buffer);

  return ret;
}

static int
print_message_buffer_old(int pid, Elf64_Addr msgq_addr, bool debug)
{
  static struct msg_queue_old msg_queue;
  int ret;

  memset(&msg_queue, 0, sizeof(msg_queue));

  if (attach(pid)) {
    DEBUG("unable to attach to %d to read string.", pid);
    return 1;
  }

  ret = read_memory((void *)&msg_queue, sizeof(msg_queue), pid, msgq_addr);

  if (detach(pid)) {
    DEBUG("unable to detach from %d.", pid);
    return 1;
  }

  if (ret > 0) {
    WARN("could not read libpulp.so message queue in process %d.", pid);
    return 1;
  }

  int size = MSGQ_OLD_BUFFER_MAX;
  int bottom = msg_queue.bottom;
  int top = msg_queue.top;
  int distance = msg_queue.distance;
  const char *buffer = msg_queue.buffer;

  if (debug)
    msgq_debug(size, bottom, top, buffer);
  else
    msgq_print(size, bottom, distance, buffer);

  return ret;
}

static int
print_message_buffer(const struct ulp_process *p, bool debug)
{
  bool old;

  Elf64_Addr msgq_addr = get_msgq_address(p, &old);

  if (!msgq_addr) {
    WARN("could not find libpulp.so message queue in process %d.", p->pid);
    return 1;
  }

  if (old) {
    return print_message_buffer_old(p->pid, msgq_addr, debug);
  } else {
    return print_message_buffer_new(p->pid, msgq_addr, debug);
  }
}

int
run_messages(struct arguments *arguments)
{
  int ret = 0;
  struct ulp_process *target = calloc(1, sizeof(struct ulp_process));

  /* Set the verbosity level in the common introspection infrastructure. */
  ulp_verbose = arguments->verbose;
  ulp_quiet = arguments->quiet;

  if (isnumber(arguments->process_wildcard)) {
    target->pid = atoi(arguments->process_wildcard);
  }
  else {
    WARN("messages only accepts PID when passing -p.");
    ret = 1;
    goto ulp_process_clean;
  }

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

struct argp_option *
get_command_option_messages(void)
{
  static struct argp_option options[] = {
    { 0, 0, 0, 0, "Options:", 0 },
    { "verbose", 'v', 0, 0, "Produce verbose output", 0 },
    { "quiet", 'q', 0, 0, "Don't produce any output", 0 },
    { "process", 'p', "process", 0, "Target process name, wildcard, or PID", 0 },
    { 0 }
  };
  return options;
}
