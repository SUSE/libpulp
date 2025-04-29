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

void exit(int);

/** @brief This should be the only way possible to exit the process if needed.
 *
 * Only use it on a catastrophic failure.
 **/
static inline __attribute__((noreturn)) void
__libpulp_unique_exit_point()
{
  exit(1);
}

#include "error.h"
#include "msg_queue.h"
#include <stdarg.h>
#include <stdio.h>

/** Holds the current error state.  Externally visible to ulp tool.  */
ulp_error_t __ulp_error_state = ENONE;

ulp_error_t
get_libpulp_error_state()
{
  return __ulp_error_state;
}

bool
libpulp_is_in_error_state()
{
  return !(get_libpulp_error_state() == ENONE);
}

void
set_libpulp_error_state(ulp_error_t state)
{
  __ulp_error_state = state;
}

void
set_libpulp_error_state_with_reason_func(const char *file, const char *func, int line,
                                         ulp_error_t state, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);

  set_libpulp_error_state(state);
  msgq_push("In file = %s, function = %s, line = %d, error state %d: ", file,
            func, line, state);
  msgq_push(fmt, args);

  va_end(args);
}

void
libpulp_assert_func(const char *file, const char *func, int line,
                    unsigned long expression)
{
  if (expression)
    return;

  msgq_push("In file = %s, function = %s, line = %d: assertion failure: %lu\n",
            file, func, line, expression);
  set_libpulp_error_state(EUNKNOWN);
}

void
libpulp_errx_func(const char *file, const char *func, int line, int eval,
                  const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  msgq_push("In file = %s, function = %s, line = %d: errx : %d ;; ", file,
            func, line, eval);
  msgq_push(fmt, args);
  va_end(args);

  set_libpulp_error_state(EUNKNOWN);
}

void
libpulp_exit_func(const char *file, const char *func, int line, int val)
{
  msgq_push("In file = %s, function = %s, line = %d: exit: %d\n", file, func,
            line, val);

  set_libpulp_error_state(EUNKNOWN);
}

void
libpulp_crash(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);

  __libpulp_unique_exit_point();
}

void
libpulp_crash_assert_func(const char *file, const char *func, int line,
                          unsigned long expression)
{
  if (expression)
    return;

  fprintf(stderr,
          "LIBPULP CATASTROPHIC FAILURE: In file = %s, function = %s, line = "
          "%d: assertion failure: %lu\n",
          file, func, line, expression);

  __libpulp_unique_exit_point();
}
