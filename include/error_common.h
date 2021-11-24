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

#ifndef ERROR_COMMON_H
#define ERROR_COMMON_H

#include <stdbool.h>
#include <errno.h>

typedef int ulp_error_t;

/** Use errno-like definitions for errors.  This way we can use system-like
 *  errors as well.
 *
 *  We reserve [0, 255] for system errors, everything else is reserved for
 *  libpulp.
 **/

#define ENONE         0     /** No error (success). */
#define EUNKNOWN      257   /** Unknown error. */
#define EBUILDID      258   /** Build Id Mismatch.  */

const char *libpulp_strerror(ulp_error_t);

#endif /* ERROR_COMMON_H  */
