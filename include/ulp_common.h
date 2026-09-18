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

#include "config.h"
#include <elf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <sys/types.h>

#include "ulp_metadata.h"

#define OUT_PATCH_NAME "metadata.ulp"
#define OUT_REVERSE_NAME "reverse.ulp"

/* Use a 512kb buffer for metadata.  This should be enough for most case
 * scenarios.  */
#define ULP_METADATA_BUF_LEN (512 * 1024)
#define ULP_PATH_LEN 256

#define ARRAY_LENGTH(v) (sizeof(v) / sizeof(*(v)))

/** Length of build id, in bytes.  */
#define BUILDID_LEN 20

/** Intel endbr64 instruction optcode.  */
#define INSN_ENDBR64 0xf3, 0x0f, 0x1e, 0xfa

/** Free whatever pointer given and set it to NULL.  */
#define FREE_AND_NULLIFY(x) \
  do { \
    if (x) { \
      free((void *)(x)); \
      (x) = NULL; \
    } \
  } \
  while (0);

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
  /** 1 = libpulp loaded.  */
  char load_state;

  /** List of patches applied.  */
  struct ulp_applied_patch *patches;
};

/** FIXME: Struct from the deprecated dependency model.  Remove and check
   compatibility with older versions of libpulp.  */
struct ulp_dependency
{
  unsigned char dep_id[32];
  char patch_id_check;
  struct ulp_dependency *next;
};

/* TODO: check/remove these OLD structures */

struct ulp_applied_patch
{
  /** ID of patch.  */
  unsigned char patch_id[32];

  /** Name of target library.  */
  const char *lib_name;

  /** Name of the patch container file (.so).  */
  const char *container_name;

  struct ulp_applied_unit *units;
  struct ulp_applied_patch *next;

  /** Patch dependency.  Not used but kept for backwards compatibility.  */
  struct ulp_dependency *deps;

  /** Timestamp of when patch was loaded.  */
  time_t timestamp;

  /** The .so handler.  */
  void *so_handler;
};

struct ulp_applied_unit
{
  /** The address of the new function, from the livepatch container.  */
  void *patched_addr;

  /** The address of the old function, from the library itself.  */
  void *target_addr;

  /** The content overwritten by the patch.  */
  char overwritten_bytes[14];

  /** FIXME: Unused, but kept as backwards compatibility with older versions of
      libpulp.   */
  char jmp_type;

  /** Next in the chain.  */
  struct ulp_applied_unit *next;
};

/** Libpulp version type.  The tripplet is incoded here, with a maximum value
    of 65535.65535.65535.  */
typedef uint64_t ulp_version_t;

/** @brief Construct ulp_version object from string.  Modifies the string
    content.  */
ulp_version_t ulp_version_from_string(char *str);

/** Build ulp_version_t from three shorts.  */
#define ULP_VERSION_TRIPLET(a, b, c) ((c) + ((b) << 16) + ((a) << 32))

/** @brief Construct string from ulp_version object.  */
const char *ulp_version_as_string(ulp_version_t ver);

/* Functions present in libcommon, linked agaist both libpulp.so and tools.  */
const char *get_basename(const char *);

const char *buildid_to_string(const unsigned char[BUILDID_LEN]);

const char *get_target_binary_name(int pid);

const char *get_current_binary_name(void);

bool isnumber(const char *str);

int parse_metadata_from_mem(struct ulp_metadata *, void *, size_t);

const char *create_path_to_tmp_file(void);

void ulp_warn(const char *, ...);
void ulp_debug(const char *, ...);

void free_metadata(struct ulp_metadata *);

bool is_directory(const char *path);

uid_t get_process_owner(pid_t pid);

#define FATAL(format, ...) \
  do { \
    fprintf(stderr, "ulp: " format "\n", ##__VA_ARGS__); \
    fprintf(stderr, "PROGRAM POTENTIALLY LEFT IN INCONSISTENT STATE."); \
  } \
  while (0)

#define WARN(format, ...) ulp_warn("ulp: " format "\n", ##__VA_ARGS__)
#define DEBUG(format, ...) ulp_debug("ulp: " format "\n", ##__VA_ARGS__)

#endif
