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

/* Define a 2Mb buffer for holding the messages.  */
#define MSGQ_BUFFER_MAX (2 * 1024 * 1024)

/* This is the circular message queue datastructure.
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
struct msg_queue
{
  char buffer[MSGQ_BUFFER_MAX]; /* Buffer holding the messages.  */
  int top;      /* Position pointing to free memory that can be written to.  */
  int bottom;   /* Position pointing to the oldest message still in buffer.  */
  int distance; /* Distance betweem top and bottom.  Should not be greater than
                   MSGQ_BUFFER_MAX.  */
};

extern struct msg_queue __ulp_msg_queue;

void msgq_push(const char *format, ...);

#endif /* MSGQ_H */
