/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2019-2021 SUSE Software Solutions GmbH
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

#include <stdio.h>
#include <string.h>

#include "ulp_common.h"
#include "error_common.h"

/** @brief Get basename of a library in the path `name`
 *
 *  This functions get the basename of a library, stripping away any path that
 *  may come in the input string `name`.
 *
 *  Example:
 *
 *   ../libs/.lib/libpulp.so
 *
 *  This function will return:
 *
 *  libpulp.so
 *
 *  @param name Path to the library, or the name of the library itself.
 *  @return Basename of the library.
 */
const char *
get_basename(const char *name)
{
  const char *base = strrchr(name, '/');

  /* If strrchr returned non-null, it means that it found the last '/' in the
   * path, so add one to get the base name.  */
  if (base)
    return base + 1;

  return name;
}

/** @brief Convert build id provided in `build_id` into string.
 *
 * Example:
 *
 * with buildid: 338aa4d16c98dda7af170cc8e2b59d259bd5d4f4
 *
 * it will return the string:
 * "338aa4d16c98dda7af170cc8e2b59d259bd5d4f4"
 *
 * The string returned by this function is statically allocated and don't
 * require `free`.
 *
 * @param build_id The build id
 *
 * @return String representing buildid in hexadecimal format.
 */
const char *
buildid_to_string(const unsigned char build_id[BUILDID_LEN])
{
  static char build_id_str[2 * BUILDID_LEN + 1];
  int i;

  memset(build_id_str, '\0', sizeof(build_id_str));

  for (i = 0; i < BUILDID_LEN; i++)
    snprintf(&build_id_str[2 * i], 3, "%02x", (unsigned)build_id[i]);

  return build_id_str;
}

const char *
libpulp_strerror(ulp_error_t errnum)
{
  static const char *const libpulp_errlist[] = {
    "Unknown error",
    "Build ID mismatch",
  };

  if (errnum > 0xFF) {
    return libpulp_errlist[errnum & 0xFF];
  } else {
    return strerror(errnum);
  }
}
