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

#define _GNU_SOURCE
#include <elf.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include "../include/ulp.h"

/* ulp data structures */
struct ulp_patching_state __ulp_state;
char __ulp_path_buffer[256] = "";
struct ulp_metadata *__ulp_metadata_ref = NULL;

// movabs 	&__ulp_get_pending, %r11
// call 	*%r11
// cmp		$0x0, %r11
// jne		<foo+2>
// jmpq		0x0(%rip) # first byte after instruction
// <data>	# address of new foo
char ulp_prologue[35] = {0x49, 0xbb,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x41, 0xff, 0xd3,
			 0x49, 0x83, 0xfb, 0x00,
			 0x75, 0x10,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0xeb, - (PRE_NOPS_LEN + 2)};

char ulp_absolute_jmp[6] = {0xff, 0x25, 0x00, 0x00, 0x00, 0x00};

__attribute__ ((constructor)) void begin(void)
{
    fprintf(stderr, "libpulp loaded...\n");
}

/* libpulp interfaces for livepatch trigger */
int __ulp_apply_patch()
{
    if (!load_patch()) {
	WARN("Patch not applied");
	return 0;
    }
    return 1;
}

void __ulp_print()
{
    fprintf(stderr, "ULP DEBUG PRINT MSG\n");
}

void * __ulp_get_path_buffer_addr()
{
    return &__ulp_path_buffer;
}

int __ulp_check_applied_patch()
{
    struct ulp_applied_patch *patch;

    __ulp_path_buffer[33] = '\0';
    patch = ulp_get_applied_patch(__ulp_path_buffer);
    if (patch) return 1;
    else return 0;
}

/* libpulp functions */
void free_metadata(struct ulp_metadata *ulp)
{
    struct ulp_unit *unit, *next_unit;
    struct ulp_object *obj, *next_obj;

    if (ulp) {
	obj = ulp->objs;
	unit = ulp->objs->units;
	while (unit) {
	    next_unit = unit->next;
	    free(unit->old_fname);
	    free(unit->new_fname);
	    free(unit);
	    unit = next_unit;
	}
	free(obj->build_id);
	if (obj->dl_handler && dlclose(obj->dl_handler)) {
	    WARN("Error closing handler for %s.", obj->name);
	}
	free(obj->name);
	free(obj);
    }

    free(ulp);
}

/* TODO: unloading needs further testing */
int unload_handlers(struct ulp_metadata *ulp)
{
    struct ulp_object *obj;
    int status = 1;
    if(ulp->so_handler && dlclose(ulp->so_handler)) {
	WARN("Error unloading patch so handler: %s", ulp->so_filename);
	status = 0;
    }
    obj = ulp->objs;
    if(obj->dl_handler && dlclose(obj->dl_handler)) {
	WARN("Error unloading patch target so handler: %s", obj->name);
	status = 0;
    }
    return status;
}

void *get_fentry_from_ulp(void *func)
{
    void *address;
    int offset = 0;
    memcpy(&offset, func + 3, 8);
    address = func + offset + 7;
    memcpy(&offset, address, sizeof(offset));
    return address;
}

// trm: should be set to take real function address out of .ulp section
void *load_so_symbol(char *fname, void *handle, int trm)
{
    void *func;
    char *error;

    func = dlsym(handle, fname);
    error = dlerror();
    if (error) {
	WARN("Unable to load function %s: %s.", fname, error);
	return NULL;
    }

    if (trm) func = get_fentry_from_ulp(func);

    return func;
}

int load_so_handlers(struct ulp_metadata *ulp)
{
    struct ulp_object *obj;
    ulp->so_handler = load_so(ulp->so_filename);

    if (!ulp->so_handler) {
	WARN("Unable to load patch dl handler.");
	unload_handlers(ulp);
	return 0;
    }

    obj = ulp->objs;
    obj->dl_handler = load_so(obj->name);
    if (!obj->dl_handler) {
	WARN("Unable to load dl handler.");
	unload_handlers(ulp);
	return 0;
    }
    return 1;
}

int unload_metadata(struct ulp_metadata *ulp)
{
    free_metadata(ulp);
    __ulp_metadata_ref = NULL;
    return 0;
}

struct ulp_metadata *load_metadata()
{
    struct ulp_metadata *ulp;
    if (__ulp_metadata_ref)
    {
	return __ulp_metadata_ref;
    }

    ulp = calloc(1, sizeof(struct ulp_metadata));
    if (!ulp) {
	WARN("Unable to allocate memory for ulp metadata");
	return 0;
    }

    __ulp_metadata_ref = ulp;
    if (!parse_metadata(ulp))
    {
	WARN("Error parsing metadata.\n");
	return 0;
    };

    return ulp;
}

int parse_metadata(struct ulp_metadata *ulp)
{
    FILE *file;
    uint32_t c;
    int i, j;
    struct ulp_object *obj;
    struct ulp_unit *unit, *prev_unit;
    struct ulp_dependency *dep, *prev_dep;

    file = fopen(__ulp_path_buffer, "rb");
    if (!file) {
	WARN("Unable to open metadata file: %s.", __ulp_path_buffer);
	return 0;
    }

    /* read metadata header information */
    ulp->objs = NULL;

    if (fread(&ulp->type, sizeof(uint8_t), 1, file) < 1) {
	WARN("Unable to read patch type.");
	return 0;
    }

    if (fread(&ulp->patch_id, sizeof(char), 32, file) < 32) {
	WARN("Unable to read patch id.");
	return 0;
    }

    /* if this is a patch revert, we don't need extra information */
    if (ulp->type == 2) return 2;

    if (fread(&c, sizeof(uint32_t), 1, file) < 1) {
	WARN("Unable to read so filename length.");
	return 0;
    }
    ulp->so_filename = calloc(c, sizeof(char));
    if (!ulp->so_filename) {
	WARN("Unable to allocate so filename buffer.");
	return 0;
    }
    if (fread(ulp->so_filename, sizeof(char), c, file) < c) {
	WARN("Unable to read so filename first.");
	return 0;
    }

    obj = calloc(1, sizeof(struct ulp_object));
    if (!obj) {
	WARN("Unable to allocate memory for the patch objects.");
	return 0;
    }
    obj->units = NULL;

    if (fread(&c, sizeof(uint32_t), 1, file) < 1) {
	WARN("Unable to read build id length (ulp).");
	return 0;
    }
    obj->build_id_len = c;

    obj->build_id = calloc(c, sizeof(char));
    if (!obj->build_id) {
	WARN("Unable to allocate build id buffer.");
	return 0;
    }
    if (fread(obj->build_id, sizeof(char), c, file) < c) {
	WARN("Unable to read build id (ulp).");
	return 0;
    }
    obj->build_id_check = 0;

    if (fread(&c, sizeof(uint32_t), 1, file) < 1) {
	WARN("Unable to read object name length.");
	return 0;
    }
    ulp->objs = obj;

    /* shared object: fill data + read patching units */
    obj->name = calloc(c, sizeof(char));
    if (!obj->name) {
	WARN("Unable to allocate object name buffer.");
	return 0;
    }
    if (fread(obj->name, sizeof(char), c, file) < c) {
	WARN("Unable to read object name.");
	return 0;
    }

    if (fread(&obj->nunits, sizeof(uint32_t), 1, file) < 1) {
	WARN("Unable to read number of patching units.");
	return 0;
    }

    /* read all patching units for object */
    for (j = 0; j < obj->nunits; j++) {
	unit = calloc(1, sizeof(struct ulp_unit));
	if (!unit) {
	    WARN("Unable to allocate memory for the patch units.");
	    return 0;
	}

	if (fread(&c, sizeof(uint32_t), 1, file) < 1) {
	    WARN("Unable to read unit old function name length.");
	    return 0;
	}
	unit->old_fname = calloc(c, sizeof(char));
	if (!unit->old_fname) {
	    WARN("Unable to allocate unit old function name buffer.");
	    return 0;
	}
	if (fread(unit->old_fname, sizeof(char), c, file) < c) {
	    WARN("Unable to read unit old function name.");
	    return 0;
	}

	if (fread(&c, sizeof(uint32_t), 1, file) < 1) {
	    WARN("Unable to read unit new function name length.");
	    return 0;
	}
	unit->new_fname = calloc(c, sizeof(char));
	if (!unit->new_fname) {
	    WARN("Unable to allocate unit new function name buffer.");
	    return 0;
	}
	if (fread(unit->new_fname, sizeof(char), c, file) < c) {
	    WARN("Unable to read unit new function name.");
	    return 0;
	}

	if (fread(&unit->old_faddr, sizeof(void *), 1, file) < 1) {
	    WARN("Unable to read old function address.");
	    return 0;
	}

	if (obj->units) {
	    prev_unit->next = unit;
	} else {
	    obj->units = unit;
	}
	prev_unit = unit;
    }

    /* read dependencies */
    if (fread(&c, sizeof(uint32_t), 1, file) < 1) {
	WARN("Unable to read number of dependencies.");
	return 0;
    }

    for (i = 0; i < c; i++) {
	dep = calloc(1, sizeof(struct ulp_dependency));
	if (!dep) {
	    WARN("Unable to allocate memory for dependency state.");
	    return 0;
	}
	if (fread(&dep->dep_id, sizeof(char), 32, file) < 32) {
	    WARN("Unable to read dependency patch id.");
	    return 0;
	}
	if (ulp->deps) {
	    prev_dep->next = dep;
	} else {
	    ulp->deps = dep;
	}
	prev_dep = dep;
    }

    if(!check_patch_sanity(ulp)) return 0;
    if(!load_so_handlers(ulp)) return 0;

    return 1;
}

void *load_so(char *obj)
{
    void *patch_obj;

    patch_obj = dlopen(obj, RTLD_LAZY);
    if (!patch_obj) {
	WARN("Unable to load shared object %s: %s.", obj, dlerror());
	return NULL;
    }

    return patch_obj;
}

int load_patch()
{
    struct ulp_metadata *ulp = NULL;
    struct ulp_object *obj;
    struct ulp_applied_patch *patch_entry;
    int patch;

    ulp = load_metadata();
    patch = ulp->type;

    switch (patch) {
	case 1:   /* apply patch */
	    patch_entry = ulp_state_update(ulp);
	    if (!patch_entry)
		break;

	    if (!ulp_apply_all_units(ulp->objs, ulp->so_handler)) {
		WARN("PATCH NOT APPLIED, reverting!");
		if (!ulp_revert_patch(patch_entry->patch_id))
		    WARN("Unable to revert patch -- Inconsistent state!");
		break;
	    }

	    goto load_patch_success;

	case 2: /* revert patch */
	    if (!ulp_can_revert_patch(ulp))
		break;
	    if (!ulp_revert_patch(ulp->patch_id)) {
		WARN("Unable to revert patch.");
		break;
	    }
	    goto load_patch_success;

	default:  /* load patch metadata error */
	    if (!patch) WARN("load patch metadata error");
	    else WARN("Unknown load metadata status");
    }
    patch = 0;

load_patch_success:
    unload_metadata(ulp);
    return patch;
}

int ulp_can_revert_patch(struct ulp_metadata *ulp)
{
    unsigned char *id = ulp->patch_id;
    int i;
    struct ulp_applied_patch *patch, *applied_patch;
    struct ulp_dependency *dep;
    struct ulp_object *obj;

    /* check if patch exists */
    applied_patch = ulp_get_applied_patch(id);
    if (!applied_patch) {
	WARN("Can't revert because patch was not applied");
	return 0;
    }

    /* check if someone depends on the patch */
    for (patch = __ulp_state.patches; patch != NULL; patch = patch->next) {
	for (dep = patch->deps; dep != NULL; dep = dep->next) {
	    if (memcmp(dep->dep_id, id, 32) == 0) {
		fprintf(stderr, "Can't revert. Dependency:\n   PATCH 0x");
		for (i = 0; i < 32; i++) {
		    fprintf(stderr, "%x ", id[i]);
		}
		fprintf(stderr, "\n");
		return 0;
	    }
	}
    }

    if (!is_object_consistent(ulp->objs)) return 1;

    return 0;
}

// TODO: check if this is still needed
int is_object_consistent(struct ulp_object *obj)
{
    char *flag;

    flag = load_so_symbol("__ulp_ret", obj->dl_handler, 0);

    if (*flag) return 0;
    return 1;
}

int ulp_apply_all_units(struct ulp_object *obj, void *patch_so)
{
    void *old_fun, *new_fun;
    struct ulp_unit *unit;

    /* only shared objs have units, this loop never runs for main obj */
    unit = obj->units;
    while (unit) {
	old_fun = load_so_symbol(unit->old_fname, obj->dl_handler, 1);
	if (!old_fun) return 0;

	new_fun = load_so_symbol(unit->new_fname, patch_so, 0);
	if (!new_fun) return 0;

	if (!ulp_patch_addr(old_fun, new_fun))  return 0;

	unit = unit->next;
    }

    return 1;
}

struct ulp_applied_patch *ulp_state_update(struct ulp_metadata *ulp)
{
    struct ulp_applied_patch *a_patch, *prev_patch;
    struct ulp_applied_unit *a_unit, *prev_unit;
    struct ulp_object *obj;
    struct ulp_unit *unit;
    struct ulp_dependency *dep, *a_dep;

    a_patch = calloc(1, sizeof(struct ulp_applied_patch));
    if (!a_patch) {
	WARN("Unable to allocate memory to update ulp state.");
	return 0;
    }
    memcpy(a_patch->patch_id, ulp->patch_id, 32);

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

    /* only shared objs have units, this loop never runs for main obj */
    while (unit != NULL) {
	a_unit = calloc(1, sizeof(struct ulp_applied_unit));
	if (!a_unit) {
	    WARN("Unable to allocate memory to update ulp state (unit).");
	    return 0;
	}

	a_unit->patched_addr = load_so_symbol(unit->old_fname,
		obj->dl_handler, 1);
	if (!a_unit->patched_addr) return 0;

	a_unit->target_addr = load_so_symbol(unit->new_fname,
		ulp->so_handler, 0);
	if (!a_unit->target_addr) return 0;

	memcpy(a_unit->overwritten_bytes, a_unit->patched_addr, 14);

	if (a_patch->units == NULL) {
	    a_patch->units = a_unit;
	    prev_unit = a_unit;
	} else {
	    prev_unit->next = a_unit;
	    prev_unit = a_unit;
	}
	unit = unit->next;
    }

    /* leave last on top of list to optmize revert */
    prev_patch = __ulp_state.patches;
    __ulp_state.patches = a_patch;
    a_patch->next = prev_patch;

    return a_patch;
}

int set_write_tgt(void *tgt_addr)
{
    unsigned long page_size, page_offset;
    void *page_start;

    page_size = getpagesize();
    page_offset = (unsigned long) tgt_addr % page_size;
    page_start = tgt_addr - page_offset;

    if (mprotect(page_start, page_size, PROT_WRITE)) {
	WARN("Memory protection set +w error");
	return 0;
    }

    if (page_offset - page_size < 5) {
	page_start = page_start + page_size;
	if (mprotect(page_start, page_size, PROT_WRITE)) {
	    WARN("Memory protection set +w error (second page)");
	    return 0;
	}
    }

    return 1;
}

int set_exec_tgt(void *tgt_addr)
{
    unsigned long page_size, page_offset;
    void *page_start;

    page_size = getpagesize();
    page_offset = (unsigned long) tgt_addr % page_size;
    page_start = tgt_addr - page_offset;

    if (mprotect(page_start, page_size, PROT_READ | PROT_EXEC)) {
	WARN("Memory protection set +x error");
	return 0;
    }

    if (page_offset - page_size < 5) {
	page_start = page_start + page_size;
	if (mprotect(page_start, page_size, PROT_READ | PROT_EXEC)) {
	    WARN("Memory protection set +x error (second page)");
	    return 0;
	}
    }

    return 1;
}

int check_patch_sanity(struct ulp_metadata *ulp)
{
    if (!check_build_id(ulp)) return 0;
    if (!check_patch_dependencies(ulp)) return 0;
    if (ulp_get_applied_patch(ulp->patch_id)) {
      WARN("Patch was already applied\n");
      return 0;
    }

    return 1;
}

int check_patch_dependencies(struct ulp_metadata *ulp)
{
    struct ulp_applied_patch *patch;
    struct ulp_dependency *dep;

    for (dep = ulp->deps; dep != NULL; dep = dep->next) {
	for (patch = __ulp_state.patches; patch != NULL; patch = patch->next) {
	    if (memcmp(patch->patch_id, dep->dep_id, 32) == 0) {
		dep->patch_id_check = 1;
		break;
	    }
	}
    }

    for (dep = ulp->deps; dep != NULL; dep = dep->next) {
	if (dep->patch_id_check == 0) {
	    WARN("Patch does not match dependencies.");
	    return 0;
	}
    }
    return 1;
}

int compare_build_ids(struct dl_phdr_info *info, size_t size, void *data)
{
    int i;
    char *note_ptr, *build_id_ptr, *note_sec;
    uint32_t note_type, build_id_len, name_len, sec_size, next = 0;
    struct ulp_object *obj;
    struct ulp_metadata *ulp;
    ulp = (struct ulp_metadata *) data;

    obj = ulp->objs;

    /* algorithm goes as follows:
     * 1 - check every object inside ulp_metadata
     * 1.1 - if object is main, match loaded object whose name length is 0
     * 1.2 - else, match ulp object and loaded object names
     * 2 - check every phdr for loaded object and match all PT_NOTE
     * 3 - trespass PT_NOTE searching for NT_GNU_BUILD_ID
     * 3.1 - once found, match contents with ulp object build id
     * 3.2 - if match, mark ulp object as checked
     * 3.3 - do not mark and break dl_iterate by returning 1
     *
     * Algorithm assumes that objects will only have one NT_GNU_BUILD_ID entry
     */

    if (strcmp(ulp->objs->name, info->dlpi_name) != 0) return 0;

    for (i = 0; i < info->dlpi_phnum; i++) {
	if (info->dlpi_phdr[i].p_type != PT_NOTE) continue;

	note_sec = (char *) (info->dlpi_phdr[i].p_vaddr + info->dlpi_addr);
	sec_size = info->dlpi_phdr[i].p_memsz;

	for (note_ptr = note_sec, note_type = (uint32_t) *(note_ptr + 8);
		note_type != NT_GNU_BUILD_ID && note_ptr < note_sec +
		sec_size;
		note_ptr = note_sec + next,
		note_type = (uint32_t) *(note_ptr + 8))
	{

	    build_id_len = (uint32_t) *(note_ptr + 4);
	    name_len = (uint32_t) *note_ptr;

	    /* fix paddings */
	    build_id_len += build_id_len % 4;
	    name_len += name_len % 4;

	    next = next + build_id_len + name_len + 12;
	}

	/* could not fid the build id in the note section, go to next sec */
	if (note_type !=  NT_GNU_BUILD_ID) continue;

	build_id_len = (uint32_t) *(note_ptr + 4);
	build_id_len += build_id_len % 4;
	if (build_id_len != ulp->objs->build_id_len) return 0;

	/* we compute, but currently do not check note names */
	name_len = (uint32_t) *note_ptr;
	name_len += name_len % 4;

	build_id_ptr = note_ptr + 12 + name_len;
	if (memcmp(ulp->objs->build_id, build_id_ptr, build_id_len) == 0) {
	    ulp->objs->build_id_check = 1;
	    return 0;
	} else {
	    return 1;
	}
    }
    return 0;
}

int all_build_ids_checked(struct ulp_metadata *ulp)
{
    struct ulp_object *obj;
    if (!ulp->objs->build_id_check) {
	WARN("Could not match patch target build id %s.", obj->name);
	return 0;
    }
    return 1;
}

int check_build_id(struct ulp_metadata *ulp)
{
    dl_iterate_phdr(compare_build_ids, ulp);
    if (!all_build_ids_checked(ulp)) return 0;
    return 1;
}

void ulp_patch_prologue_layout(void *old_fentry, void *pending)
{
    memcpy(old_fentry, ulp_prologue, sizeof(ulp_prologue));
    memcpy(old_fentry + 2, &pending, 8); // TODO: fix the size here
}

void *ulp_get_pending()
{
	return &__ulp_get_pending;
}

void ulp_patch_addr_absolute(void *old_fentry, void *new_faddr)
{
   // absolute jump patching
    memcpy(old_fentry + 19, ulp_absolute_jmp, sizeof(ulp_absolute_jmp));
    memcpy(old_fentry + 19 + sizeof(ulp_absolute_jmp), &new_faddr, sizeof(void *));
}

int ulp_patch_addr(void *old_faddr, void *new_faddr)
{
    void *old_fentry = old_faddr - PRE_NOPS_LEN;
    void *pending;
    pending = ulp_get_pending();
    //__ulp_pending = 1;

    if (!set_write_tgt(old_faddr))
	return 0;

    ulp_patch_prologue_layout(old_fentry, pending);
    ulp_patch_addr_absolute(old_fentry, new_faddr);

    if (!set_exec_tgt(old_faddr))
	return 0;

    return 1;
}

struct ulp_applied_patch *ulp_get_applied_patch(unsigned char *id)
{
    struct ulp_applied_patch *patch;

    for (patch = __ulp_state.patches; patch != NULL; patch = patch->next)
	if (memcmp(patch->patch_id, id, 32) == 0) return patch;

    return NULL;
}

int ulp_revert_patch(unsigned char *id)
{
    struct ulp_applied_patch *patch;

    patch = ulp_get_applied_patch(id);

    if (ulp_revert_all_units(patch)) {
	if (!ulp_state_remove(patch)) {
	    WARN("Problem updating state. Program may be inconsistent.");
	    return 0;
	}
    }

    return 1;
}

int ulp_state_remove(struct ulp_applied_patch *rm_patch)
{
    struct ulp_applied_patch *patch;
    struct ulp_applied_unit *unit, *next_unit;
    struct ulp_dependency *dep, *next_dep;
    int found = 0;

    /* take it out from applied patches list */
    if (__ulp_state.patches == rm_patch) {
	found = 1;
	__ulp_state.patches = rm_patch->next;
    } else {
	for (patch = __ulp_state.patches; patch != NULL; patch = patch->next) {
	    if (patch == rm_patch) {
		found = 1;
		patch->next = rm_patch->next;
		break;
	    }
	}
    }

    if (!found) return 0;

    /* free all units from it */
    for (unit = rm_patch->units; unit != NULL; unit = next_unit) {
	next_unit = unit->next;
	free(unit);
    }

    /* free all deps from it */
    for (dep = rm_patch->deps; dep != NULL; dep = next_dep) {
	next_dep = dep->next;
	free(dep);
    }

    /* free it */
    free(rm_patch);

    return 1;
}

int ulp_revert_all_units(struct ulp_applied_patch *patch)
{
    struct ulp_applied_unit *unit;

    int consistent = 1;

    for (unit = patch->units; unit != NULL; unit = unit->next) {
	if (!ulp_unpatch_addr(unit->patched_addr, unit->overwritten_bytes)) {
	    WARN("Unable to revert patch.");
	    if (!consistent) {
		WARN("Fatal error reverting patch. Program is inconsistent.");
		exit(-1);
	    } else {
		WARN("Error reverting patch unit.");
		return 0;
	    }
	} else {
	    consistent = 0;
	}
    }
    return 1;
}

int ulp_unpatch_addr(void *addr, char *previous)
{
    if (!set_write_tgt(addr)) return 0;

    memcpy(addr, previous, 14);

    if (!set_exec_tgt(addr)) return 0;

    return 1;
}

/* these are here for debugging reasons :) */
void dump_ulp_patching_state(void)
{
    struct ulp_applied_patch *a_patch;
    struct ulp_applied_unit *a_unit;
    struct ulp_dependency *dep;
    int i;

    fprintf(stderr, "----- ULP state dump -----\n");
    for (a_patch = __ulp_state.patches; a_patch != NULL;
	    a_patch = a_patch->next)
    {
	fprintf(stderr, "* PATCH 0x");
	for (i = 0; i < 32; i++) {
	    fprintf(stderr, "%x.", a_patch->patch_id[i]);
	}
	fprintf(stderr, "\n");
	for (dep = a_patch->deps; dep != NULL; dep = dep->next) {
	    fprintf(stderr, "* DEPENDs 0x");
	    for (i = 0; i < 32; i++) {
		fprintf(stderr, "%x.", dep->dep_id[i]);
	    }
	    fprintf(stderr, "\n");
	}

	for (a_unit = a_patch->units; a_unit != NULL; a_unit = a_unit->next)
	    fprintf(stderr, "** %p %p\n", a_unit->patched_addr,
		    a_unit->target_addr);
    }
    fprintf(stderr, "----- End of dump ------\n");
}
