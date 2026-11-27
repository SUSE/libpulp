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

#ifndef MSGQ_H
#define MSGQ_H

#include <stdarg.h>

/** Define a 256Kb buffer for holding the messages in the old queue.  */
#define MSGQ_BUFFER_MAX (256 * 1024)

/** Define a 2Mb buffer for holding the messages in the old queue.  */
#define MSGQ_OLD_BUFFER_MAX (2 * 1024 * 1024)

/** This is the circular message queue datastructure.
 *
 * It works on a fixed-size buffer and operates maintaining three variables:
 *
 *  - Top.
 *  - Bottom.
 *  - Distance.
 *
 * Take the following illustration as example, after inserting the strings:
 *
 *   - hhhhhhhhhhhhhh.
 *   - iiiiii
 *   - jjjjjjj
 *
 * Which will get the queue in the following state:
 *
 *  hhhhhhhhhhhhhh.iiiiii.jjjjjjj...
 *  B                             T
 *
 * Where 'B' represents the bottom position, 'T' represents the top position,
 * and the '.' represents the \0 character.
 *
 * If we insert the string 'kkkkkkk' next, notice that there is not enough
 * space in the buffer for it, so 'T' wraps back to the beginning of the queue,
 * overwrite part of the sequence of 'h', increments 'B', and write the message
 * in the opened space, which results in the following state:
 *
 *  kkkkkkk.hhhhhh.iiiiii.jjjjjjj...
 *          T      B
 *
 * resulting in the circular queue behaviour. When reading this queue, the user
 * should start reading from the bottom position.
 */

/** Define the same structure that is used by old versions of libpulp (<0.3.18)  */
struct msg_queue
{
  /** Size of the queue.  Must match the size of MSGQ_BUFFER_MAX.  */
  int size;

  /** Position pointing to free memory that can be written to.  */
  int top;

  /** Position pointing to the oldest message still in buffer.  */
  int bottom;

  /** Distance betweem top and bottom. Should not be greater than
   * MSGQ_BUFFER_MAX.  */
  int distance;

  /** Buffer holding the messages.  */
  char buffer[MSGQ_BUFFER_MAX];
};

/** Define the same structure that is used by old versions of libpulp (<0.3.18)  */
struct msg_queue_old
{
  /** Buffer holding the messages.  */
  char buffer[MSGQ_OLD_BUFFER_MAX];

  /** Position pointing to free memory that can be written to.  */
  int top;

  /** Position pointing to the oldest message still in buffer.  */
  int bottom;

  /** Distance betweem top and bottom. Should not be greater than
   * MSGQ_BUFFER_MAX.  */
  int distance;
};

extern struct msg_queue __ulp_msg_queue_new;

void msgq_push(const char *format, ...);
void msgq_vpush(const char *format, va_list);

#endif /* MSGQ_H */
