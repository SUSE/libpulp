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

#include <dlfcn.h>
#include <link.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>

#include "ulp_common.h"

/* ULP Structures */

/** The ulp_detour_root object represents a single function that is patched.
 *
 * This object is created when a function is patched, and is unique per
 * function. If another patch modifies that function, this object is modified
 * rather than create a new one.  A new object is only created if a new
 * function is patched.
 */
struct ulp_detour_root
{
  /** Index of the detour root. Increases as new roots are created.  */
  unsigned int index;

  /** Address of patched function.  */
  void *patched_addr;

  /** Next root in the root chain.  */
  struct ulp_detour_root *next;

  /** Detour objects associated with this root.  */
  struct ulp_detour *detours;
};

/** The ulp_detour object represents a new function comming from a patch.
 *
 * This object is created when a new function is set as a replacement to a old
 * function that was livepatched.  If another patch modifies that function, a
 * new object is created and the old one is set as inactive.
 */
struct ulp_detour
{
  /** ID of origin patch.  */
  unsigned char patch_id[32];

  /** ID of the detour object.  Increases as patches are applied. */
  unsigned long universe;

  /** Address to the new function.  */
  void *target_addr;

  /** Is patch active?  */
  char active;

  /** Next in chain.  */
  struct ulp_detour *next;
};

struct dl_phdr_info;

/* libpulp livepatching interfaces */
int __ulp_apply_patch();

void __ulp_print();

/* functions */
void free_metadata(struct ulp_metadata *ulp);

int unload_handlers(struct ulp_metadata *ulp);

void *load_so_symbol(char *fname, void *handle);

int load_so_handlers(struct ulp_metadata *ulp);

int unload_metadata(struct ulp_metadata *ulp);

struct ulp_metadata *load_metadata(int *err);

int parse_metadata(struct ulp_metadata *ulp);

void *load_so(char *obj);

int load_patch(void);

int ulp_can_revert_patch(const unsigned char *id);

int is_object_consistent(struct ulp_object *obj);

int ulp_apply_all_units(struct ulp_metadata *ulp);

struct ulp_applied_patch *ulp_state_update(struct ulp_metadata *ulp);

int check_patch_sanity(struct ulp_metadata *ulp);

int check_patch_dependencies(struct ulp_metadata *ulp);

int compare_build_ids(struct dl_phdr_info *info, size_t size, void *data);

int all_build_ids_checked(struct ulp_metadata *ulp);

int check_build_id(struct ulp_metadata *ulp);

void ulp_patch_addr_absolute(void *old_faddr, void *new_faddr);

int ulp_patch_addr(void *old_faddr, void *new_faddr, int enable);

struct ulp_applied_patch *ulp_get_applied_patch(const unsigned char *id);

int ulp_revert_patch(unsigned char *id);

int ulp_state_remove(unsigned char *id);

int ulp_revert_all_units(unsigned char *patch_id);

int get_active_func_dl_info(unsigned long p, Dl_info *info);

int ulp_unpatch_addr(void *addr, char *previous);

unsigned int get_next_function_index();

unsigned int push_new_detour(unsigned long universe, unsigned char *patch_id,
                             struct ulp_detour_root *root, void *new_faddr);

struct ulp_detour_root *get_detour_root_by_address(void *addr);

struct ulp_detour_root *get_detour_root_by_index(unsigned int idx);

void dump_ulp_patching_state(void);

void dump_ulp_detours(void);

int memory_protection_get(uintptr_t addr);

void save_to_register(void *);
