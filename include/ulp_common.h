/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017-2021 SUSE Software Solutions GmbH
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

#ifndef _ULP_LIB_COMMON_
#define _ULP_LIB_COMMON_

#include <stdbool.h>
#include <stdint.h>

#define OUT_PATCH_NAME "metadata.ulp"
#define OUT_REVERSE_NAME "reverse.ulp"

#define WARN(format, ...) fprintf(stderr, "ulp: " format "\n", ##__VA_ARGS__)

/* Use a 512kb buffer for metadata.  This should be enough for most case
 * scenarios.  */
#define ULP_METADATA_BUF_LEN (512 * 1024)
#define ULP_PATH_LEN 256
#define RED_ZONE_LEN 128

#define ARRAY_LENGTH(v) (sizeof(v) / sizeof(*(v)))

/** Length of build id, in bytes.  */
#define BUILDID_LEN 20

extern __thread int __ulp_pending;

/** Used on __tls_get_addr(tls_index *).  */
typedef struct
{
  /** Internal module index.  */
  unsigned long ti_module;

  /** Symbol index in tls section.  */
  unsigned long ti_offset;
} tls_index;

struct ulp_patching_state
{
  char load_state;
  struct ulp_applied_patch *patches;
};

struct ulp_metadata
{
  unsigned char patch_id[32];
  char *so_filename;
  void *so_handler;
  struct ulp_object *objs;
  uint32_t ndeps;
  struct ulp_dependency *deps;
  uint32_t nrefs;
  struct ulp_reference *refs;
  uint8_t type;
};

struct ulp_object
{
  uint32_t build_id_len;
  uint32_t build_id_check;
  char *build_id;
  char *name;
  void *flag;
  uint32_t nunits;
  struct ulp_unit *units;
};

struct ulp_unit
{
  char *old_fname;
  char *new_fname;
  void *old_faddr;
  struct ulp_unit *next;
};

struct ulp_dependency
{
  unsigned char dep_id[32];
  char patch_id_check;
  struct ulp_dependency *next;
};

struct ulp_reference
{
  char *target_name;
  char *reference_name;
  uintptr_t target_offset;
  uintptr_t patch_offset;
  bool tls;
  struct ulp_reference *next;
};

/* TODO: check/remove these OLD structures */

struct ulp_applied_patch
{
  unsigned char patch_id[32];
  const char *lib_name;
  const char *container_name;
  struct ulp_applied_unit *units;
  struct ulp_applied_patch *next;
  struct ulp_dependency *deps;
};

struct ulp_applied_unit
{
  void *patched_addr;
  void *target_addr;
  char overwritten_bytes[14];
  char jmp_type;
  struct ulp_applied_unit *next;
};

/* Functions present in libcommon, linked agaist both libpulp.so and tools.  */
const char *get_basename(const char *);

const char *buildid_to_string(const unsigned char[BUILDID_LEN]);

const char *get_target_binary_name(int);

const char *get_current_binary_name(void);

bool isnumber(const char *str);

const char *create_path_to_tmp_file(void);

#endif
