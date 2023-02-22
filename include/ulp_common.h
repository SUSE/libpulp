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

#include <elf.h>
#include <stdbool.h>
#include <stdint.h>

#define OUT_PATCH_NAME "metadata.ulp"
#define OUT_REVERSE_NAME "reverse.ulp"

/* Use a 512kb buffer for metadata.  This should be enough for most case
 * scenarios.  */
#define ULP_METADATA_BUF_LEN (512 * 1024)
#define ULP_PATH_LEN 256
#define RED_ZONE_LEN 128

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
  /** 1 = libpulp loaded.  */
  char load_state;

  /** List of patches applied.  */
  struct ulp_applied_patch *patches;
};

struct ulp_metadata
{
  /** BuildID of patch.  */
  unsigned char patch_id[32];

  /** Name of the patch container.  */
  char *so_filename;

  /** dlopen handle of the patch container.  */
  void *so_handler;

  /** Content of a patch for a single library.  */
  struct ulp_object *objs;
  uint32_t ndeps;

  /** Dependencies of the patch.
      FIXME: This has been deprecated and should be removed.  */
  struct ulp_dependency *deps;

  uint32_t nrefs;

  /** Number of indirect references to variables (private or tls or unexported
      variables).  FIXME: This should be moved into ulp_object, but be careful
        with compatibility with older versions of libpulp.  */
  struct ulp_reference *refs;

  /** Type of patch (apply a patch, remove a patch).  */
  uint8_t type;

  /** Comment section used to hold information that may be useful for a human,
      like CVE or bugzilla references.  */
  char *comments;
};

/** Represents a */
struct ulp_object
{
  uint32_t build_id_len;

  /** Flags if there was a match with the library's build id loaded in the
      target program.  */
  uint32_t build_id_check;

  /** Build id of target library ship in the livepatch.  */
  char *build_id;

  /** Name of the library to be livepatched.  */
  char *name;

  /** FIXME: Unused, but kept for compatibility with older libpulps.  */
  void *flag;

  /** Number of units.  FIXME: Is this really necessary?  */
  uint32_t nunits;

  /** Number of units to patch (symbols).  */
  struct ulp_unit *units;
};

/** Represents a single symbol that needs to be patched in the livepatch.  */
struct ulp_unit
{
  /** Name of the symbol (function) that will be replaced in the library.  */
  char *old_fname;

  /** Name of the symbol (function) that will replace the function in library.
   */
  char *new_fname;

  /** Address of function that will be patched.  */
  void *old_faddr;
  struct ulp_unit *next;
};

/** FIXME: Struct from the deprecated dependency model.  Remove and check
   compatibility with older versions of libpulp.  */
struct ulp_dependency
{
  unsigned char dep_id[32];
  char patch_id_check;
  struct ulp_dependency *next;
};

/** Struct encapsulating references to variables.  This is used to livepatch
    static variables (i.e. private to the compilation unit), tls variables,
    and variables which are not exposed by the module at all.  This can also
    be used to bypass linking issues.  */
struct ulp_reference
{
  /** holds the name of the variable in the target library which we want to
      reference to.  */
  char *target_name;

  /** holds the name of the variable in the livepatch container which we want
      the reference address to be written to.  */
  char *reference_name;

  /** Reference to the variable in the library.  */
  uintptr_t target_offset;

  /** Reference to the variable where we will write the reference to.  */
  uintptr_t patch_offset;

  /** Is this a Thread Local Storage variable?  */
  bool tls;

  /** Next reference in chain.  */
  struct ulp_reference *next;
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

#define FATAL(format, ...) \
  do { \
    fprintf(stderr, "ulp: " format "\n", ##__VA_ARGS__); \
    fprintf(stderr, "PROGRAM POTENTIALLY LEFT IN INCONSISTENT STATE."); \
  } \
  while (0)

#define WARN(format, ...) ulp_warn("ulp: " format "\n", ##__VA_ARGS__)
#define DEBUG(format, ...) ulp_debug("ulp: " format "\n", ##__VA_ARGS__)

#endif
