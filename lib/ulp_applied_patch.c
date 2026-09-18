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

#define _GNU_SOURCE

#include "ulp_common.h"
#include "ulp_applied_patch.h"
#include "ulp.h"
#include "msg_queue.h"
#include "symbol_loader.h"

#include <stdlib.h>
#include <string.h>

#include "error.h"

struct ulp_patching_state __ulp_state = { 0, NULL };

/** @brief TODO: merge with ulp_apply_all_units.  There seems to be no reason
    why these two things are separated.  */
struct ulp_applied_patch *
ulp_state_update(struct ulp_metadata *ulp)
{
  struct ulp_applied_patch *a_patch, *prev_patch = NULL;
  struct ulp_applied_unit *a_unit, *prev_unit = NULL;
  struct ulp_object *obj;
  struct ulp_unit *unit;
  struct ulp_dependency *dep, *a_dep;
  const char *basename_target;

  a_patch = calloc(1, sizeof(struct ulp_applied_patch));
  if (!a_patch) {
    WARN("Unable to allocate memory to update ulp state.");
    return 0;
  }

  memcpy(a_patch->patch_id, ulp->patch_id, 32);

  a_patch->lib_name = strndup(get_basename(ulp->objs->name), ULP_PATH_LEN);
  if (!a_patch->lib_name) {
    WARN("Unable to allocate filename buffer state.");
    return 0;
  }

  a_patch->container_name = strndup(ulp->so_filename, ULP_PATH_LEN);
  if (!a_patch->container_name) {
    WARN("Unable to allocate filename buffer state.");
    return 0;
  }

  for (dep = ulp->deps; dep != NULL; dep = dep->next) {
    a_dep = calloc(1, sizeof(struct ulp_dependency));
    if (!a_dep) {
      WARN("Unable to allocate memory to ulp state dependency.");
      return 0;
    }

    *a_dep = *dep;
    a_dep->next = a_patch->deps;
    a_patch->deps = a_dep;
  }

  obj = ulp->objs;
  unit = obj->units;

  basename_target = get_basename(obj->name);

  /* Copy the .so handler to the new created applied_patch object.  */
  a_patch->so_handler = ulp->so_handler;

  /* only shared objs have units, this loop never runs for main obj */
  while (unit != NULL) {
    a_unit = calloc(1, sizeof(struct ulp_applied_unit));
    if (!a_unit) {
      WARN("Unable to allocate memory to update ulp state (unit).");
      return 0;
    }

    a_unit->patched_addr = get_loaded_symbol_addr(
        basename_target, unit->old_fname, unit->old_faddr);
    if (!a_unit->patched_addr) {
      WARN("Symbol %s not found in %s.", unit->old_fname, basename_target);
      return 0;
    }

    a_unit->target_addr = load_so_symbol(unit->new_fname, a_patch->so_handler);
    if (!a_unit->target_addr) {
      return 0;
    }

    memcpy(a_unit->overwritten_bytes, a_unit->patched_addr, 14);

    if (a_patch->units == NULL) {
      a_patch->units = a_unit;
      prev_unit = a_unit;
    }
    else {
      prev_unit->next = a_unit;
      prev_unit = a_unit;
    }
    unit = unit->next;
  }

  /* Insert timestamp.  */
  struct timespec t;
  clock_gettime(CLOCK_REALTIME, &t);
  a_patch->timestamp = t.tv_sec;

  /* leave last on top of list to optmize revert */
  prev_patch = __ulp_state.patches;
  __ulp_state.patches = a_patch;
  a_patch->next = prev_patch;

  return a_patch;
}


/** @brief Remove applied patch from the patches list.
 *
 * If a patch removal is issued, this function will remove the patch from the
 * patch list.
 *
 * @brief id    Patch id to remove.
 *
 * @return      0 if no patch to remove, 1 if patch found.
 *
 */
int
ulp_state_remove(unsigned char *id)
{
  struct ulp_applied_patch **patch, *patch_to_remove = NULL;
  struct ulp_applied_unit *unit, *next_unit;
  struct ulp_dependency *dep, *next_dep;

  /* take it out from applied patches list */
  /* Find the patch in the patch chain*/
  for (patch = &__ulp_state.patches; *patch != NULL; patch = &(*patch)->next) {
    /* Check if this is the patch we want.  */
    if (memcmp((*patch)->patch_id, id, 32) == 0) {
      /* Remove it from the patch chain.  */
      patch_to_remove = *patch;
      *patch = (*patch)->next;

      /* We have found what we need.  */
      break;
    }
  }

  if (!patch_to_remove) {
    return 0;
  }

  /* Free all units from it.  */
  for (unit = patch_to_remove->units; unit != NULL; unit = next_unit) {
    next_unit = unit->next;
    FREE_AND_NULLIFY(unit);
  }

  /* Free all deps from it.  */
  for (dep = patch_to_remove->deps; dep != NULL; dep = next_dep) {
    next_dep = dep->next;
    FREE_AND_NULLIFY(dep);
  }

  FREE_AND_NULLIFY(patch_to_remove->lib_name);
  FREE_AND_NULLIFY(patch_to_remove->container_name)
  FREE_AND_NULLIFY(patch_to_remove);

  return 1;
}

struct ulp_applied_patch *
ulp_get_applied_patch(const unsigned char *id)
{
  struct ulp_applied_patch *patch;

  for (patch = __ulp_state.patches; patch != NULL; patch = patch->next)
    if (memcmp(patch->patch_id, id, 32) == 0)
      return patch;

  return NULL;
}

/** @brief Revert all live patches associated with library `lib_name`
 *
 * The user may have applied a series of live patches on a library named
 * `lib_name` in the program. This function will revert every patch so
 * that all functions are reverted into their original state.
 *
 * @param lib_name Base name of the library.
 * @return 0 on success, anything else on failure.
 */
int
revert_all_patches_from_lib(const char *lib_name)
{
  struct ulp_applied_patch *patch = __ulp_state.patches;
  struct ulp_applied_patch *next;

  const char *lib_basename = get_basename(lib_name);

  int ret = ENOTARGETLIB;

  /* Paranoid: check if the path buffer didn't overflow.  */
  if ((ptrdiff_t)(lib_basename - lib_name) >= ULP_PATH_LEN) {
    WARN("Path buffer overflow, aborting revert...");
    return EOVERFLOW;
  }

  while (patch) {
    next = patch->next;
    if (!strncmp(lib_basename, patch->lib_name, ULP_PATH_LEN)) {
      ret = ulp_can_revert_patch(patch->patch_id);
      if (ret) {
        continue;
      }

      ret = ulp_revert_patch(patch->patch_id);
      if (ret)
        return ret;
    }

    patch = next;
  }

  /* In case there is no patch, then check if the target library is indeed
     loaded.  */
  if (ret == ENOTARGETLIB &&
      get_loaded_library_base_addr(lib_basename) != (void *)0xFF) {
    return ENOPATCH;
  }

  return ret;
}


/** @brief Check if a patch with patchid = `id` can be reverted.
 *
 * Check if the patch with its id = `id` can be reverted.
 *
 * @param id    The id of patch to analyze.
 * @return      0 if success, anything else if error.
 */
int
ulp_can_revert_patch(const unsigned char *id)
{
  int i;
  struct ulp_applied_patch *patch, *applied_patch;
  struct ulp_dependency *dep;

  /* check if patch exists */
  applied_patch = ulp_get_applied_patch(id);
  if (!applied_patch) {
    WARN("Can't revert because patch was not applied");
    return ENOTAPPLIED;
  }

  /* check if someone depends on the patch */
  for (patch = __ulp_state.patches; patch != NULL; patch = patch->next) {
    for (dep = patch->deps; dep != NULL; dep = dep->next) {
      if (memcmp(dep->dep_id, id, 32) == 0) {
        msgq_push("Can't revert. Dependency:\n   PATCH 0x");
        for (i = 0; i < 32; i++) {
          msgq_push("%x ", id[i]);
        }
        msgq_push("\n");
        return EDEPEND;
      }
    }
  }

  return 0;
}
