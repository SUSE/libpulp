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

#ifndef ERROR_H
#define ERROR_H

#include "error_common.h"
#include <stdbool.h>

/* Error checking routines.  */

void exit(int);

/** @brief Get libpulp error state.
 *
 * If a fatal error has occured, libpulp cannot continue livepatching processes
 * because it may be into an unexpected state.  This function queries if
 * libpulp is in an error state.
 **/
ulp_error_t get_libpulp_error_state(void);


/** @brief Set libpulp error state.
 *
 * If a fatal error has occured, libpulp cannot continue livepatching processes
 * because it may be into an unexpected state.  This function sets its state
 * so livepatching can be marked as disabled for any reason.
 **/
void set_libpulp_error_state(ulp_error_t);
void set_libpulp_error_state_with_reason_func(const char *file, const char *func,
                                              int line, ulp_error_t state,
                                              const char *fmt, ...);

/** @brief Macro which passes the current file, function and line number for
 * logging for the `set_libpulp_error_state_with_reason_func`.
 */
#define set_libpulp_error_state_with_reason(...) \
  set_libpulp_error_state_with_reason_func(__FILE__, __func__, __LINE__, __VA_ARGS__)

/** @brief Check if libpulp is in an fatal error state.
 *
 * If a fatal error has occured, libpulp cannot continue livepatching processes
 * because it may be into an unexpected state.
 *
 * @return true if in error state, false if not.
 **/
bool libpulp_is_in_error_state(void);

/** @brief Assert that the following expression is true.  */
void libpulp_assert_func(const char *file, const char *func, int line,
                         unsigned long expression);

/** @brief Macro which passes the current file, function and line number for
 * logging.  */
#define libpulp_assert(expr) \
  libpulp_assert_func(__FILE__, __func__, __LINE__, (unsigned long)(expr))

/** @brief Libpulp's version of `errx`
 *
 *  This function works like libc's `errx`, however instead of quiting the
 *  process it put libpulp into a state that livepatches are blocked.
 * */
void libpulp_errx_func(const char *file, const char *func, int line, int eval,
                       const char *fmt, ...);

/** @brief Macro which passes the current file, function and line number for
 * logging.  */
#define libpulp_errx(...) \
  libpulp_errx_func(__FILE__, __func__, __LINE__, __VA_ARGS__)

/** @brief Libpulp's version of `exit`
 *
 *  This function works like libc's `exit`, however instead of quiting the
 *  process it put libpulp into a state that livepatches are blocked.
 * */
void libpulp_exit_func(const char *file, const char *func, int line, int val);

#define libpulp_exit(val) libpulp_exit_func(__FILE__, __func__, __LINE__, val)

/** @brief This function will indeed crash the process with an error message.
 *
 * Should be used with care. This should be used when the library is
 * initializing and something really bad happened (e.g. dlsym not found, which
 * means malloc can't be called in the original process. That certainly will
 * turns into a disaster so it is better to crash in the beginning rather than
 * trying to continue the user's process.
 **/
void __attribute__((noreturn)) libpulp_crash(const char *fmt, ...);

/** @brief Assert that the following expression is true.  Crash the program if
 * not.  */
void libpulp_crash_assert_func(const char *file, const char *func, int line,
                               unsigned long expression);

#define libpulp_crash_assert(expr) \
  libpulp_crash_assert_func(__FILE__, __func__, __LINE__, (unsigned long)expr)

/** Poison any function that makes the process to abort.  */
#ifndef DISABLE_ERR_POISON
#ifdef assert
#undef assert
#endif
#pragma GCC poison errx exit assert abort
#endif

#endif /* ERROR_H  */
