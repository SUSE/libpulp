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

#include <ctype.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

#include "error_common.h"
#include "ulp_common.h"

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
  static const char *const libpulp_errlist[] = __ULP_ERRLIST;

  if (0xFF < errnum &&
      errnum < EUNKNOWN + (int)ARRAY_LENGTH(libpulp_errlist)) {
    return libpulp_errlist[errnum & 0xFF];
  }
  else {
    return strerror(errnum);
  }
}

/** @brief Get target program name
 *
 * For instance, assume that the program is named "binary", which the
 * user launched with "./binary".  This function will return the string
 * "binary".
 *
 * @return Target program binary's name.
 */
const char *
get_target_binary_name(int pid)
{
  static char binary_name[PATH_MAX];

  char fname[PATH_MAX];
  char cmdline[PATH_MAX];

  snprintf(fname, sizeof(fname), "/proc/%d/comm", pid);
  FILE *fp = fopen(fname, "r");
  if (fgets(cmdline, sizeof(cmdline), fp) != NULL) {
    strncpy(binary_name, get_basename(cmdline), PATH_MAX - 1);

    /* Remove any newlines from the string.  */
    for (int i = 0; i < (PATH_MAX - 1) && binary_name[i] != '\0'; i++) {
      if (binary_name[i] == '\n') {
        binary_name[i] = '\0';
        break;
      }
    }
  }
  fclose(fp);

  return binary_name;
}

/** @brief Get current program name
 *
 * For instance, assume that the program is named "binary", which the
 * user launched with "./binary".  This function will return the string
 * "binary".
 *
 * @return This program binary's name.
 */
const char *
get_current_binary_name()
{
  return get_target_binary_name(getpid());
}

/** @brief Check if string is actually a number.
 *
 * @param str  The string to check.
 *
 * @return     True if `str` is a number, False if not.
 */
bool
isnumber(const char *str)
{
  int i;

  if (str == NULL || *str == '\0')
    return false;

  for (i = 0; str[i] != '\0'; i++) {
    if (!isdigit(str[i]))
      return false;
  }

  return true;
}

/** @brief Creates a path to a temporary file.
 *
 * This function creates a path to a temporary file. The string returned is not
 * malloc'ed, so if you want to save the string somewhere you should `strdup`
 * it.
 *
 * @return Path to a temporary file.
 *
 */
const char *
create_path_to_tmp_file(void)
{
  const char *tmp_prefix = "/tmp/ulp-";
  static char buffer[24];
  FILE *f;

  /* Loop until we find an unused path.  If we are running multiple packer
     instances, we could eventually get a clash. */
  bool conflict = false;
  do {
    unsigned token;
    ssize_t n = getrandom(&token, sizeof(unsigned), 0);
    if (n != sizeof(unsigned)) {
      WARN("Failure in getrandom()");
      return NULL;
    }

    snprintf(buffer, 24, "%s%u", tmp_prefix, token);
    f = fopen(buffer, "r");
    if (f) {
      conflict = true;
      fclose(f);
    }
  }
  while (conflict);

  /* Create file so other packer instances do not hold it.  */
  f = fopen(buffer, "w");
  fwrite("", 1, 0, f);
  fclose(f);

  return buffer;
}

/** Used to keep track of how many bytes we have consumed.  We cannot surpass
 *  ULP_METADATA_BUF_LEN.  */
static long cur;
static long meta_len;
static long __attribute__((noinline))
read_from_mem(void *to, size_t size, long count, void *from)
{
#define REMAINING_BUF(x) (meta_len - x)

  char *cfrom = from;
  long final_cnt = count * size;

  if (final_cnt > REMAINING_BUF(cur))
    final_cnt = REMAINING_BUF(cur);

  memcpy(to, cfrom + cur, final_cnt);
  cur += final_cnt;

  return final_cnt;

#undef REMAINING_BUF
}

int
parse_metadata_from_mem(struct ulp_metadata *ulp, void *src, size_t size)
{
  meta_len = size;
  cur = 0;

  uint32_t c;
  uint32_t i, j;
  struct ulp_object *obj;
  struct ulp_unit *unit, *prev_unit = NULL;
  struct ulp_dependency *dep, *prev_dep = NULL;
  struct ulp_reference *ref, *prev_ref = NULL;

  DEBUG("reading live patch metadata from memory");

  /* read metadata header information */
  ulp->objs = NULL;

  if (read_from_mem(&ulp->type, sizeof(uint8_t), 1, src) < 1) {
    WARN("Unable to read patch type.");
    return EINVALIDULP;
  }

  if (read_from_mem(&ulp->patch_id, sizeof(char), 32, src) < 32) {
    WARN("Unable to read patch id.");
    return EINVALIDULP;
  }

  if (read_from_mem(&c, sizeof(uint32_t), 1, src) < 1) {
    WARN("Unable to read so filename length.");
    return EINVALIDULP;
  }

  ulp->so_filename = calloc(c + 1, sizeof(char));
  if (!ulp->so_filename) {
    WARN("Unable to allocate so filename buffer.");
    return EINVALIDULP;
  }

  if (read_from_mem(ulp->so_filename, sizeof(char), c, src) < c) {
    WARN("Unable to read so filename.");
    return EINVALIDULP;
  }

  if (*ulp->so_filename == '\0') {
    WARN("livepatch container path is empty.");
    return EINVALIDULP;
  }

  obj = calloc(1, sizeof(struct ulp_object));
  if (!obj) {
    WARN("Unable to allocate memory for the patch objects.");
    return ENOMEM;
  }

  ulp->objs = obj;
  obj->units = NULL;

  if (read_from_mem(&c, sizeof(uint32_t), 1, src) < 1) {
    WARN("Unable to read build id length (trigger).");
    return EINVALIDULP;
  }
  obj->build_id_len = c;
  obj->build_id = calloc(c, sizeof(char));
  if (!obj->build_id) {
    WARN("Unable to allocate build id buffer.");
    return EINVALIDULP;
  }

  if (read_from_mem(obj->build_id, sizeof(char), c, src) < c) {
    WARN("Unable to read build id.");
    return EINVALIDULP;
  }

  obj->build_id_check = 0;

  if (read_from_mem(&c, sizeof(uint32_t), 1, src) < 1) {
    WARN("Unable to read object name length.");
    return EINVALIDULP;
  }

  /* shared object: fill data + read patching units */
  obj->name = calloc(c + 1, sizeof(char));
  if (!obj->name) {
    WARN("Unable to allocate object name buffer.");
    return EINVALIDULP;
  }

  if (read_from_mem(obj->name, sizeof(char), c, src) < c) {
    WARN("Unable to read object name.");
    return EINVALIDULP;
  }

  if (ulp->type == 2) {
    /*
     * Reverse patches do not have patching units nor dependencies,
     * so return right away.
     */
    return 0;
  }

  if (read_from_mem(&obj->nunits, sizeof(uint32_t), 1, src) < 1) {
    WARN("Unable to read number of patching units.");
    return 1;
  }

  /* read all patching units for object */
  for (j = 0; j < obj->nunits; j++) {
    unit = calloc(1, sizeof(struct ulp_unit));
    if (!unit) {
      WARN("Unable to allocate memory for the patch units.");
      return ENOMEM;
    }

    if (read_from_mem(&c, sizeof(uint32_t), 1, src) < 1) {
      WARN("Unable to read unit old function name length.");
      return EINVALIDULP;
    }

    unit->old_fname = calloc(c + 1, sizeof(char));
    if (!unit->old_fname) {
      WARN("Unable to allocate unit old function name buffer.");
      return EINVALIDULP;
    }

    if (read_from_mem(unit->old_fname, sizeof(char), c, src) < c) {
      WARN("Unable to read unit old function name.");
      return EINVALIDULP;
    }

    if (read_from_mem(&c, sizeof(uint32_t), 1, src) < 1) {
      WARN("Unable to read unit new function name length.");
      return EINVALIDULP;
    }

    unit->new_fname = calloc(c + 1, sizeof(char));
    if (!unit->new_fname) {
      WARN("Unable to allocate unit new function name buffer.");
      return EINVALIDULP;
    }

    if (read_from_mem(unit->new_fname, sizeof(char), c, src) < c) {
      WARN("Unable to read unit new function name.");
      return EINVALIDULP;
    }

    if (read_from_mem(&unit->old_faddr, sizeof(void *), 1, src) < 1) {
      WARN("Unable to read old function address.");
      return EINVALIDULP;
    }

    if (obj->units) {
      prev_unit->next = unit;
    }
    else {
      obj->units = unit;
    }
    prev_unit = unit;
  }

  /* read dependencies */
  if (read_from_mem(&c, sizeof(uint32_t), 1, src) < 1) {
    WARN("Unable to read number of dependencies.");
    return EINVALIDULP;
  }

  for (i = 0; i < c; i++) {
    dep = calloc(1, sizeof(struct ulp_dependency));
    if (!dep) {
      WARN("Unable to allocate memory for dependency state.");
      return ENOMEM;
    }
    if (read_from_mem(&dep->dep_id, sizeof(char), 32, src) < 32) {
      WARN("Unable to read dependency patch id.");
      return EINVALIDULP;
    }
    if (ulp->deps) {
      prev_dep->next = dep;
    }
    else {
      ulp->deps = dep;
    }
    prev_dep = dep;
  }

  /* read number of static data items */
  if (read_from_mem(&ulp->nrefs, sizeof(uint32_t), 1, src) < 4) {
    WARN("Unable to read the number of static data references in livepatch");
    return EINVALIDULP;
  }

  /* read all static data reference items */
  for (i = 0; i < ulp->nrefs; i++) {
    ref = calloc(1, sizeof(struct ulp_reference));
    if (!ref) {
      WARN("Unable to allocate memory for static data reference.");
      return errno;
    }

    /* read local variable name */
    if (read_from_mem(&c, sizeof(uint32_t), 1, src) < 4) {
      WARN("Unable to read local variable name.");
      return EINVALIDULP;
    }
    ref->target_name = calloc(c, sizeof(char));
    if (!ref->target_name) {
      WARN("Unable to allocate memory for static data reference name.");
      return errno;
    }
    if (read_from_mem(ref->target_name, sizeof(char), c, src) < c) {
      WARN("Unable to read target variable name.");
      return EINVALIDULP;
    }

    /* read reference name */
    if (read_from_mem(&c, sizeof(uint32_t), 1, src) < 4) {
      WARN("Unable to read reference name size");
      return EINVALIDULP;
    }
    ref->reference_name = calloc(c, sizeof(char));
    if (!ref->reference_name) {
      WARN("Unable to allocate memory for static data reference name.");
      return errno;
    }
    if (read_from_mem(ref->reference_name, sizeof(char), c, src) < c) {
      WARN("Unable to read reference name.");
      return EINVALIDULP;
    }

    /* read reference offset within the target library */
    if (read_from_mem(&ref->target_offset, sizeof(uintptr_t), 1, src) < 8) {
      WARN("Unable to read target offset within target library");
      return EINVALIDULP;
    }

    /* read reference offset within the patch object */
    if (read_from_mem(&ref->patch_offset, sizeof(uintptr_t), 1, src) < 8) {
      WARN("Unable to read patch offset.");
      return EINVALIDULP;
    }

    /* read if variable is tls within the patch object */
    if (read_from_mem(&ref->tls, sizeof(bool), 1, src) < 1) {
      WARN("Unable to read TLS field.");
      return EINVALIDULP;
    }

    if (ulp->refs) {
      prev_ref->next = ref;
    }
    else {
      ulp->refs = ref;
    }
    prev_ref = ref;
  }

  return 0;
}
