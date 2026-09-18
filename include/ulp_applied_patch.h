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

#ifndef _ULP_APPLIED_PATCH_
#define _ULP_APPLIED_PATCH_

#include "config.h"

#include "ulp_metadata.h"

struct ulp_dependency;
struct ulp_applied_unit;
struct ulp_applied_patch;

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

struct ulp_applied_patch *ulp_state_update(struct ulp_metadata *ulp);

struct ulp_applied_patch *ulp_get_applied_patch(const unsigned char *id);

int ulp_can_revert_patch(const unsigned char *id);

int ulp_state_remove(unsigned char *id);

int revert_all_patches_from_lib(const char *lib_name);

#endif
