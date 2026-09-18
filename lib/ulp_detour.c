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
#include "ulp_detour.h"
#include "ulp_common.h"
#include "symbol_loader.h"
#include "arch_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <link.h>
#include <dlfcn.h>

#include "error.h"

struct ulp_detour_root *__ulp_root = NULL;
unsigned int __ulp_root_index_counter = 0;

/* Functions from other modules.  See what to do with them.  */
void ulp_patch_addr_absolute(void *old_faddr, void *new_faddr);
int ulp_patch_addr(void *old_faddr, void *new_faddr, int enable);
void *memwrite(void *dest, const void *src, size_t n);


extern unsigned long __ulp_global_universe;

/** @brief Get next root index and update the global counter.
 *
 * Every time a livepatch function is updated, this counter gets updated.
 */
unsigned int
get_next_function_index()
{
  return __ulp_root_index_counter++;
}

/* END Functions from other modules.  */

/** @brief Push new detour object into root object.
 *
 * This function will push a new detour object (reference to new function)
 * into the root object (old function).
 *
 * @param universe     Global index state.
 * @param patch_id     ID of patch.
 * @param root         Root object representing old function.
 * @param new_faddr    New function whose detour object will be created.
 *
 * @return             0 if error 1 if success.
 */
unsigned int
push_new_detour(unsigned long universe, unsigned char *patch_id,
                struct ulp_detour_root *root, void *new_faddr)
{
  struct ulp_detour *detour, *detour_aux;

  detour = calloc(1, sizeof(struct ulp_detour));
  if (!detour) {
    WARN("Unable to allocate memory for ulp detour");
    return 0;
  }

  detour_aux = root->detours;
  root->detours = detour;
  detour->next = detour_aux;
  detour->target_addr = new_faddr;
  detour->universe = universe;
  detour->active = 1;
  memcpy(detour->patch_id, patch_id, 32);

  return 1;
}

/** @brief Get the detour root (patched function) by index.
 *
 * @param idx    Index to querry.
 * @return       NULL if not found, pointer to root object if found.
 */
struct ulp_detour_root *
get_detour_root_by_index(unsigned int idx)
{
  struct ulp_detour_root *r;
  for (r = __ulp_root; r != NULL && r->index != idx; r = r->next)
    ;

  return r;
}

/** @brief Get the detour root (patched function) by its address.
 *
 * @param addr   Address of function to querry.
 * @return       NULL if not found, pointer to root object if found.
 */
struct ulp_detour_root *
get_detour_root_by_address(void *addr)
{
  struct ulp_detour_root *r;
  for (r = __ulp_root; r != NULL && r->patched_addr != addr; r = r->next)
    ;

  return r;
}

/** @brief Push a new empty detour object to the beginning to detour list.
 *
 * @return       New detour object.
 */
struct ulp_detour_root *
push_new_root(void)
{
  struct ulp_detour_root *root, *root_aux;

  root = calloc(1, sizeof(struct ulp_detour_root));
  if (!root) {
    WARN("unable to allocate memory for ulp detour root");
    return NULL;
  }

  /* Append the new root into the start of the chain.  */
  root_aux = __ulp_root;
  __ulp_root = root;
  root->next = root_aux;

  return root;
}

/** @brief Revert all units applied to given patch id.
 *
 * This function will revert all units applied by a patch which matches the
 * given patch id, applying the units from a previous patch if available.
 *
 * @param patch_id    ID of the patch to revert.
 *
 * @return 1 if success or failure.
 */
int
ulp_revert_all_units(unsigned char *patch_id)
{
  struct ulp_detour_root *r;
  struct ulp_detour *d;
  struct ulp_detour *d2;
  struct ulp_detour *dactive;

  for (r = __ulp_root; r != NULL; r = r->next)
    for (d = r->detours; d != NULL; d = d->next)
      if (memcmp(d->patch_id, patch_id, 32) == 0) {

        /* Deactivate this patch. */
        d->active = 0;

        /* Find the most recent live patch that is active. */
        dactive = NULL;
        for (d2 = r->detours; d2 != NULL; d2 = d2->next) {
          if (d2->active) {
            dactive = d2;
            /* Newest elements of the list come first. */
            break;
          }
        }

        /* Update the function prologue. */
        if (!dactive) {
          /* There is no previous patch in this function.  */
          ulp_patch_addr(r->patched_addr, NULL, false);
        }
        else {
          ulp_patch_addr(r->patched_addr, dactive->target_addr, true);
        }
      }

  return 1;
}

/** @brief Apply parsed metadata object content.
 *
 * This function will apply all units (function replacements) in the
 * livepatch, as well as the private data references.
 *
 * @param ulp       The parsed ulp_metadata object.
 * @return          0 if success, anything else if error.
 */
int
ulp_apply_all_units(struct ulp_metadata *ulp)
{
  int retcode;
  void *old_fun, *new_fun;
  void *patch_so = ulp->so_handler;
  struct ulp_object *obj = ulp->objs;
  struct ulp_unit *unit;
  struct ulp_detour_root *root;
  struct ulp_reference *ref;

  __ulp_global_universe++;

  /* only shared objs have units, this loop never runs for main obj */
  unit = obj->units;
  while (unit) {
    old_fun = get_loaded_symbol_addr(get_basename(obj->name), unit->old_fname,
                                     unit->old_faddr);
    if (!old_fun)
      return ENOOLDFUNC;

    new_fun = load_so_symbol(unit->new_fname, patch_so);
    if (!new_fun)
      return ENONEWFUNC;

    root = get_detour_root_by_address(old_fun);
    if (!root) {
      root = push_new_root();
      if (!root)
        return EUNKNOWN;

      root->index = get_next_function_index();
      root->patched_addr = old_fun;
    }

    if (!(push_new_detour(__ulp_global_universe, ulp->patch_id, root,
                          new_fun))) {
      WARN("error setting ulp data structure\n");
      return EUNKNOWN;
    }

    if ((retcode = ulp_patch_addr(old_fun, new_fun, true)) > 0) {
      WARN("error patching address %p", old_fun);
      return retcode;
    }

    unit = unit->next;
  }

  /*
   * Each live patch loads a new shared object into the target process. If the
   * live patch references static data from the target library, the references
   * must be fixed so that they point to the actual address where the target
   * library has been loaded, so find the base address.
   *
   * XXX: The metadata file and its corresponding data structures within
   *      libpulp seem to allow more than one live patch object per live patch.
   *      However, the implementation is incomplete, so assume that there is a
   *      single object, and access ulp->objs directly.
   */
  struct link_map map_data;
  struct link_map *map_ptr;
  uintptr_t target_base;
  int tls_idx;
  uintptr_t patch_base;
  const char *target_basename = get_basename(ulp->objs->name);

  target_base = (uintptr_t)get_loaded_library_base_addr(target_basename);
  tls_idx = get_loaded_library_tls_index(target_basename);
  if (target_base == 0xFF) {
    WARN("Unable to find target library load address of %s", target_basename);
    return ENOADDRESS;
  }

  map_ptr = &map_data;
  memset(map_ptr, 0, sizeof(struct link_map));
  retcode = dlinfo(patch_so, RTLD_DI_LINKMAP, &map_ptr);
  if (retcode == -1) {
    WARN("Error in call to dlinfo: %s", dlerror());
    return EUNKNOWN;
  }
  if (map_ptr->l_addr == 0) {
    WARN("Unable to find target library load address: %s", dlerror());
    return ENOADDRESS;
  }
  patch_base = map_ptr->l_addr;

  /* Now patch static data references in the live patch object */
  ref = ulp->refs;
  while (ref) {
    uintptr_t patch_address;
    if (ref->patch_offset == 0) {
      /* In case the user did not specify the patch offset, try to find the
         symbol's address by its name.  */
      patch_address =
          (uintptr_t)load_so_symbol(ref->reference_name, patch_so);

      if (patch_address == 0) {
        return ENONEWFUNC;
      }

      ref->patch_offset = patch_address - patch_base;
    }
    else {
      patch_address = patch_base + ref->patch_offset;
    }

    if (ref->tls) {
      tls_index ti = { .ti_module = tls_idx,
                       .ti_offset = ref->target_offset - TLS_DTV_OFFSET };
      memwrite((void *)patch_address, &ti, sizeof(ti));
    }
    else {
      uintptr_t target_address = target_base + ref->target_offset;
      memwrite((void *)patch_address, &target_address, sizeof(void *));
    }
    ref = ref->next;
  }

  return 0;
}

void
dump_ulp_detours(void)
{
  struct ulp_detour_root *r;
  struct ulp_detour *d;
  int i;
  fprintf(stderr, "====== ULP Roots ======\n");
  for (r = __ulp_root; r != NULL; r = r->next) {
    fprintf(stderr, "* ROOT:\n");
    fprintf(stderr, "* Index: %d\n", r->index);
    fprintf(stderr, "* Patched addr: %p\n", r->patched_addr);
    fprintf(stderr, "----- ULP DETOURS -----\n");
    for (d = r->detours; d != NULL; d = d->next) {
      fprintf(stderr, "  * DETOUR:\n");
      fprintf(stderr, "  * Universe: %ld\n", d->universe);
      fprintf(stderr, "  * Target addr: %p\n", d->target_addr);
      fprintf(stderr, "  * Active: ");
      if (d->active)
        fprintf(stderr, "yep\n");
      else
        fprintf(stderr, "nop\n");
      fprintf(stderr, "  * Patch ID: ");
      for (i = 0; i < 16; i++)
        fprintf(stderr, "%x.", d->patch_id[i]);
      fprintf(stderr, "\n              ");
      for (i = 16; i < 32; i++)
        fprintf(stderr, "%x.", d->patch_id[i]);
      fprintf(stderr, "\n========================\n");
    }
  }
}

