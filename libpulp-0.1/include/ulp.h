/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017 SUSE Linux GmbH
 *
 *  This file is part of libpulp.
 *
 *  libpulp is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  libpulp is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with libpulp.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  Author: Joao Moreira <jmoreira@suse.de>
 */

#include <stdio.h>
#include <signal.h>
#include <stddef.h>
#include <dlfcn.h>
#include "ulp_common.h"

/* structures */

struct ulp_patching_state {
    struct ulp_applied_patch *patches;
};

struct ulp_applied_patch {
    unsigned char patch_id[32];
    struct ulp_applied_unit *units;
    struct ulp_applied_patch *next;
    struct ulp_dependency *deps;
};

struct ulp_applied_unit {
    void *patched_addr;
    void *target_addr;
    char overwritten_bytes[14];
    char jmp_type;
    struct ulp_applied_unit *next;
};

/* libpulp livepatching interfaces */
int __ulp_apply_patch();

void __ulp_print();

void * __ulp_get_path_buffer_addr();

/* functions */
void free_metadata(struct ulp_metadata *ulp);

int unload_handlers(struct ulp_metadata *ulp);

void *load_so_symbol(char *fname, void *handle);

int load_so_handlers(struct ulp_metadata *ulp);

int unload_metadata(struct ulp_metadata *ulp);

struct ulp_metadata *load_metadata();

int parse_metadata(struct ulp_metadata *ulp);

void *load_so(char *obj);

int load_patch();

int ulp_can_revert_patch(struct ulp_metadata *ulp);

int is_object_consistent(struct ulp_object *obj);

int ulp_apply_all_units(struct ulp_object *obj, void *patch_so);

struct ulp_applied_patch *ulp_state_update(struct ulp_metadata *ulp);

int set_write_tgt(void *tgt_addr);

int set_exec_tgt(void *tgt_addr);

int check_patch_sanity(struct ulp_metadata *ulp);

int check_patch_dependencies(struct ulp_metadata *ulp);

int compare_build_ids(struct dl_phdr_info *info, size_t size, void *data);

int all_build_ids_checked(struct ulp_metadata *ulp);

int check_build_id(struct ulp_metadata *ulp);

void ulp_patch_addr_relative(void *old_faddr, ptrdiff_t rel_tgt);

void ulp_patch_addr_absolute(void *old_faddr, void *new_faddr);

int ulp_patch_addr(void *old_faddr, void *new_faddr);

struct ulp_applied_patch *ulp_get_applied_patch(unsigned char *id);

int ulp_revert_patch(unsigned char *id);

int ulp_state_remove(struct ulp_applied_patch *rm_patch);

int ulp_revert_all_units(struct ulp_applied_patch *patch);

int get_active_func_dl_info(unsigned long p, Dl_info *info);

int ulp_unpatch_addr(void *addr, char *previous);

void dump_ulp_patching_state(void);
