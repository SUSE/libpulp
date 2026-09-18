/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017-2026 SUSE Software Solutions GmbH
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

#ifndef _ULP_LIB_METADATA_
#define _ULP_LIB_METADATA_

#include <config.h>
#include <stdint.h>
#include <stdbool.h>

/* This file specifies operations with the `metadata` object.  The ULP metadata
   is a description of what functions we must patch.  */

struct ulp_object;
struct ulp_reference;
struct ulp_unit;
struct ulp_metadata;
struct ulp_dependency;

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

/** Represents a single target library.  */
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

void free_metadata(struct ulp_metadata *ulp);

int unload_handlers(struct ulp_metadata *ulp);

int unload_metadata(struct ulp_metadata *ulp);

struct ulp_metadata *load_metadata(int *err);

int load_so_handlers(struct ulp_metadata *ulp);

int parse_metadata(struct ulp_metadata *ulp);

#endif
