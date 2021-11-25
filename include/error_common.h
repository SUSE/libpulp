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

#include <errno.h>
#include <stdbool.h>

typedef int ulp_error_t;

/** Use errno-like definitions for errors.  This way we can use system-like
 *  errors as well.
 *
 *  We reserve [0, 255] for system errors, everything else is reserved for
 *  libpulp.
 **/

/* clang-format off */
#define ENONE           0 /** No error (success).  */
#define EUNKNOWN      256 /** Unknown error.  */
#define EBUILDID      257 /** Build Id Mismatch.  */
#define ETARGETHOOK   258 /** Error attaching to process.  */
#define ENODEBUGTAG   259 /** Process without DT_DEBUG tag.  */
#define ENOLINKMAP    260 /** No link map in object.  */
#define ENOPHDR       261 /** Invalid program header.  */
#define ENOPENTRY     262 /** Unable to find process entry address.  */
#define ENOLIBPULP    263 /** Libpulp not found.  */
#define ETHRDATTACH   264 /** Thread attach failure.  */
#define ETHRDDETTACH  265 /** Thread dettach failure.  */
#define EINVALIDULP   266 /** Invalid ULP file.  */

/** Table used to map error code to message.  Define it here so that it is
 *  easier for it being maintained.
 */
#define __ULP_ERRLIST \
  { \
    "Unknown error", \
    "Build ID mismatch", \
    "Error attaching to process", \
    "Process without debug tag", \
    "No link map in object", \
    "Invalid program header", \
    "Unable to find process entry address", \
    "Libpulp not found", \
    "Thread attach failure", \
    "Thread dettach failure", \
    "Invalid .ulp file", \
  }
/* clang-format on */

const char *libpulp_strerror(ulp_error_t);

#endif /* ERROR_COMMON_H  */
