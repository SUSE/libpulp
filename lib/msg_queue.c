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

#include "msg_queue.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Create an externally visible msg_queue object that will be read with ptrace.
 * It will be read by ulp_messages (tools/messages.c) using ptrace. */

struct msg_queue __ulp_msg_queue;

static char msg[MSGQ_BUFFER_MAX];

static void
msgq_strpush(const char *msg, size_t msg_size)
{
  /* Write the msg_queue values in variables for briefness.  */
  int top = __ulp_msg_queue.top;
  int bottom = __ulp_msg_queue.bottom;
  int distance = __ulp_msg_queue.distance;
  char *buffer = __ulp_msg_queue.buffer;

  /* In case the message is empty or it is too large for the buffer, don't
   * bother even trying to insert it.  */
  if (*msg == '\0' || msg_size > MSGQ_BUFFER_MAX)
    return;

  /* To understand what the `top` and `bottom` means, read messages.h in the
   * include folder.
   *
   * Here, in case the message would not fit the available space in the end
   * of the queue, insert it in the beginning, and account for this jump.
   */
  if (top + msg_size >= MSGQ_BUFFER_MAX) {
    memset(&buffer[top], '\0', MSGQ_BUFFER_MAX - top);
    distance += MSGQ_BUFFER_MAX - top;
    top = 0;
  }

  /* Remember that this is a circular queue. Therefore, the distance between
   * top and bottom should not pass the size of the queue, else we have a
   * buffer overflow. In case when inserting the message would make the top
   * marker overlap the bottom marker, we must eliminate the first
   * inserted contents from the buffer.  This basically means that the bottom
   * should move towards the top until enough space is available.  */
  while (distance + msg_size >= MSGQ_BUFFER_MAX) {
    int travel = strlen(&buffer[bottom]) + 1;
    bottom = (bottom + travel) % MSGQ_BUFFER_MAX;

    /* We may have reached a sequence of null characters because of the top
     * being set to zero, which makes the end of the buffer to be filled with
     * null characters.  Account for this too.  */
    while (buffer[bottom] == '\0') {
      bottom = (bottom + 1) % MSGQ_BUFFER_MAX;
      travel++;
    }

    distance -= travel;
  }

  /* Finally, commit the message to the buffer.  */
  memcpy(&buffer[top], msg, msg_size);

  /* Update other structures.  */
  distance += msg_size;
  top = (top + msg_size) % MSGQ_BUFFER_MAX;

  __ulp_msg_queue.top = top;
  __ulp_msg_queue.bottom = bottom;
  __ulp_msg_queue.distance = distance;
}

/* Push a message into the message queue.
 *
 * @param format - printf like string.
 * */
void
msgq_push(const char *format, ...)
{
  va_list arglist;
  size_t msg_size;

  /* Expand the format string with the arguments provided. vsnprintf will
   * return the size of the string, therefore, the size of the object will
   * be +1 because of the null character in the end of the string.  */
  va_start(arglist, format);
  msg_size = vsnprintf(msg, MSGQ_BUFFER_MAX, format, arglist) + 1;
  va_end(arglist);

  msgq_strpush(msg, msg_size);
}

/* Push a message into the message queue.
 *
 * @param format - printf like string.
 * */
void
msgq_vpush(const char *format, va_list arglist)
{
  size_t msg_size;

  /* Expand the format string with the arguments provided. vsnprintf will
   * return the size of the string, therefore, the size of the object will
   * be +1 because of the null character in the end of the string.  */
  msg_size = vsnprintf(msg, MSGQ_BUFFER_MAX, format, arglist) + 1;

  msgq_strpush(msg, msg_size);
}

/** @brief Post a warning message in libpulp's circular buffer.
 *
 * Implement this here because we have a common library that is compiled once
 * for both libpulp.so and tools.
 *
 * @param format  printf formated message
 */
void
ulp_warn(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  msgq_vpush(format, args);
  va_end(args);
}

void
ulp_debug(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  msgq_vpush(format, args);
  va_end(args);
}
