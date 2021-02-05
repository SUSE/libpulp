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
#include <unistd.h>

#include <libparameters.h>

int
main (void)
{
  char buffer[128] = "X";
  ssize_t ret;

  /* Signal readiness. */
  printf ("Waiting for input.\n");

  /*
   * When a thread that is in the middle of a syscall receives a signal,
   * the syscall gets interrupted. On some occasions, such as when there
   * are no handlers registered for the signal, or when the SA_RESTART
   * flag is in effect (see sigaction(2)), the kernel arranges an
   * automatic restarting of the syscall to happen when the thread is
   * rescheduled, and it does so by subtracting one instruction from the
   * program counter.
   *
   * Notice, however, that the subtracting happens only immediately
   * before the rescheduling, and it can't be easily detected from a
   * tracer, such as gdb or libpulp's tools. The tracer sees a program
   * counter that points to the next instruction after the syscall,
   * i.e.: it doesn't see the subtraction.
   *
   * Now, since libpulp hijacks the target process, modifies the
   * program counter of a selected thread, and asks the kernel to resume
   * execution; the subtraction mechanism could be consumed, and the
   * actual restarting of the syscall could be lost. If that happens,
   * programs that do not handle syscall interruption would break.
   * Besides, even if the change in behavior would not be catastrophic,
   * it would make live patching less transparent.
   *
   * The following program intentionally exits in error if the read
   * syscall is not restarted.
   */
  errno = 0;
  ret = read (STDIN_FILENO, buffer, 1);

  if (ret < 0) {
    if (errno == EINTR) {
      printf ("read syscall interrupted but not restarted.\n");
    }
    printf ("read syscall error code: %d", errno);
    return 1; /* Libpulp should restart syscalls on its own. */
  }
  if (ret == 0) {
    printf ("End of file.\n");
    return 1; /* The test driver is not expected to send EOF. */
  }

  int_params (1, 2, 3, 4, 5, 6, 7, 8);
  float_params (1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
  return 0; /* At least one byte was read. */
}
