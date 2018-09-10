/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017-2018 SUSE Linux GmbH
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

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <link.h>
#include <dirent.h>
#include <bfd.h>
#include <stddef.h>
#include <fcntl.h>
#include <sys/user.h>
#include <unistd.h>

#include "ptrace.h"
#include "introspection.h"
#include "../../include/ulp_common.h"

ulp_process target;
ulp_addresses addr;
struct ulp_metadata ulp;

int parse_file_symtab(ulp_dynobj *obj)
{
    bfd *file;
    int symtab_len;

    file = bfd_openr(obj->filename, NULL);
    if (!file)
    {
	WARN("bfd_openr error.");
	return 1;
    }
    bfd_check_format(file, bfd_object);

    symtab_len = bfd_get_symtab_upper_bound(file);
    if (!symtab_len)
    {
	WARN("bfd_get_symtab_upper_bound error.");
	return 2;
    }

    obj->symtab = (asymbol **) malloc(symtab_len);
    if (!obj->symtab)
    {
	WARN("symtab malloc error.");
	return 3;
    }

    obj->symtab_len = bfd_canonicalize_symtab(file, obj->symtab);
    return 0;
}

asymbol **get_main_symtab()
{
    ulp_dynobj *o;
    for (o = target.dynobjs; o != NULL; o = o->next)
    {
	if (o->main) return o->symtab;
    }
    return NULL;
}

int get_main_symtab_length()
{
    ulp_dynobj *o;
    for (o = target.dynobjs; o != NULL; o = o->next)
	if (o->main) return o->symtab_len;

    return 0;
}

int dig_main_link_map(struct link_map *main_link_map)
{
    Elf64_Addr dyn_addr, link_map, link_map_addr, r_debug = 0;
    int nentries, i, r_map_offset;
    ElfW(Dyn) dyn;
    asymbol **symtab;

    symtab = get_main_symtab();
    nentries = get_main_symtab_length();

    for (i = 0; i < nentries; i++) {
	if (strcmp(bfd_asymbol_name(symtab[i]),"_DYNAMIC")==0) {
	    dyn_addr = bfd_asymbol_value(symtab[i]);
	    break;
	}
    }
    /* fix for PIE executables */
    dyn_addr = dyn_addr + target.load_bias;

    if (i == nentries) {
	WARN("error parsing _DYNAMIC.");
	return 1;
    };

    while(1) {
	if (read_memory((char *) &dyn, sizeof(ElfW(Dyn)), target.pid, dyn_addr))
	{
	    WARN("error reading _DYNAMIC array.");
	    free(symtab);
	    return 2;
	}
	if (dyn.d_tag == DT_NULL) {
	    WARN("error searching for r_debug.");
	    free(symtab);
	    return 3;
	}
	if (dyn.d_tag == DT_DEBUG) {
	    r_debug = dyn.d_un.d_ptr;
	    break;
	}
	dyn_addr = dyn_addr + sizeof(ElfW(Dyn));
    }
    r_map_offset = offsetof(struct r_debug, r_map);
    link_map_addr = r_debug + r_map_offset;

    if (read_memory((char *) &link_map, sizeof(void *), target.pid,
		link_map_addr))
    {
	WARN("error reading link_map address.");
	return 4;
    }

    if (read_memory((char *) main_link_map, sizeof(struct link_map), target.pid,
		link_map))
    {
	WARN("error reading link_map address.");
	return 5;
    }

    free(symtab);
    return 0;
}

int parse_threads(int pid)
{
    struct ulp_thread *t, *prev_t;
    char *format_str, *dirname;
    DIR *tasks_dir;
    struct dirent *dir;
    unsigned int tid;

    format_str = "/proc/%d/task/";
    dirname = calloc(strlen(format_str) + 10, 1);
    sprintf(dirname, format_str, pid);

    prev_t = NULL;

    tasks_dir = opendir(dirname);
    if (tasks_dir) {
	dir = readdir(tasks_dir);
	while (dir != NULL) {
	    tid = atoi(dir->d_name);
	    /* add main thread in front, after this loop */
	    if (!tid || tid == pid)
	    {
		dir = readdir(tasks_dir);
		continue;
	    }

	    t = calloc(sizeof(struct ulp_thread), 1);
	    if (!t)
	    {
		WARN("Unable to allocate thread structure.");
		return 1;
	    }
	    t->tid = tid;
	    t->next = prev_t;
	    t->consistent = 0;
	    prev_t = t;

	    dir = readdir(tasks_dir);
	}
    }

    t = calloc(sizeof(struct ulp_thread), 1);
    if (!t)
    {
	WARN("Unable to allocate main thread structure.");
	return 1;
    }
    t->tid = pid;
    t->next = prev_t;
    t->consistent = 0;
    target.threads = t;

    return 0;
}

Elf64_Addr get_loaded_symbol_addr(struct ulp_dynobj *obj, char *sym)
{
    unsigned int i;
    Elf64_Addr sym_addr, ptr = 0;
    long int var;

    for (i = 0; i < obj->symtab_len; i++) {
	if (strcmp(bfd_asymbol_name(obj->symtab[i]), sym)==0) {
	    ptr = bfd_asymbol_value(obj->symtab[i]);
	}
    }

    if (ptr == 0) return 0;

    sym_addr = ptr + obj->link_map.l_addr;

    return sym_addr;
}

int dig_load_bias(struct ulp_dynobj *obj)
{
    int auxv, i;
    char *format_str, *filename;
    Elf64_auxv_t at;
    uint64_t entry;
    Elf64_Addr _start;

    if (!obj->symtab)
    {
	WARN("error: initialize process first.");
	return 1;
    }

    format_str = "/proc/%d/auxv";
    filename = calloc(strlen(format_str) + 10, 1);
    sprintf(filename, format_str, target.pid);

    auxv = open(filename, O_RDONLY);
    if (!auxv)
    {
	WARN("error: unable to open auxv.");
	return 2;
    }

    do {
	read(auxv, &at, sizeof(Elf64_auxv_t));
	if (at.a_type == AT_ENTRY) {
	    entry = at.a_un.a_val;
	    break;
	}
    } while (at.a_type != AT_NULL);

    for (i = 0; i < obj->symtab_len; i++) {
	if (strcmp(bfd_asymbol_name(obj->symtab[i]),"_start")==0) {
	    _start = bfd_asymbol_value(obj->symtab[i]);
	    break;
	}
    }

    target.load_bias = entry - _start;
    free(filename);
    return 0;
}

int parse_main_dynobj(char *objname)
{
    struct ulp_dynobj *obj;
    /* calloc initializes all to zero */
    obj = calloc(sizeof(struct ulp_dynobj), 1);
    if (!obj)
    {
	WARN("Unable to allocate object structure.");
	return 1;
    }
    obj->filename = objname;

    if (parse_file_symtab(obj)) return 2;
    obj->main = 1;
    obj->next = target.dynobjs;

    obj->trigger = get_loaded_symbol_addr(obj, "__ulp_trigger");
    obj->loop = get_loaded_symbol_addr(obj, "__ulp_loop");
    obj->path_buffer = get_loaded_symbol_addr(obj, "__ulp_get_path_buffer");
    obj->check = get_loaded_symbol_addr(obj, "__ulp_check_patched");

    target.dynobjs = obj;

    if (dig_load_bias(obj)) return 3;
    if (dig_main_link_map(&obj->link_map)) return 4;

    return 0;
}

int is_main_object_parsed()
{
    ulp_dynobj *o;

    for (o = target.dynobjs; o != NULL; o = o->next)
    {
	if (o->main) return 1;
    }

    return 0;
}

struct link_map *parse_lib_dynobj(struct link_map *link_map_addr)
{
    struct ulp_dynobj *obj;
    struct link_map *link_map;

    char *libname;
    /* calloc initializes all to zero */
    obj = calloc(sizeof(struct ulp_dynobj), 1);
    link_map = calloc(sizeof(struct link_map), 1);

    if (read_memory((char *) link_map, sizeof(struct link_map), target.pid,
		(Elf64_Addr) link_map_addr))
    {
	WARN("error reading link_map address.");
	return NULL;
    }

    if (read_string(&libname, target.pid, (Elf64_Addr) link_map->l_name))
    {
	WARN("error reading link_map string.");
	return NULL;
    }

    if (libname[0] != '/') return link_map;

    obj->filename = libname;
    obj->next = target.dynobjs;
    target.dynobjs = obj;

    /* ensure that PIE was verified */
    if (!is_main_object_parsed()) return NULL;

    if (parse_file_symtab(obj)) return NULL;

    obj->link_map = *link_map;
    obj->trigger = get_loaded_symbol_addr(obj, "__ulp_trigger");
    obj->loop = get_loaded_symbol_addr(obj, "__ulp_loop");
    obj->consistency = get_loaded_symbol_addr(obj, "__ulp_get_flag");
    obj->path_buffer = get_loaded_symbol_addr(obj, "__ulp_get_path_buffer");
    obj->check = get_loaded_symbol_addr(obj, "__ulp_check_patched");

    return link_map;
}

struct link_map get_link_map(char *name)
{
    ulp_dynobj *o;
    for (o = target.dynobjs; o != NULL; o = o->next)
    {
	if (strcmp(o->filename, name)==0) break;
    }
    return o->link_map;
}

int initialize_data_structures(int pid, char *livepatch)
{
    char *format_str;
    char *filename;
    struct link_map main_link_map, *obj_link_map, *aux_link_map;
    ulp_dynobj *o;

    target.pid = pid;

    if (!load_patch_info(livepatch))
    {
	WARN("Unable to load patch info.");
	return 1;
    }

    bfd_init();

    format_str = "/proc/%d/exe";
    filename = calloc(strlen(format_str) + 10, 1);
    sprintf(filename, format_str, pid);

    if (parse_threads(target.pid)) return 2;

    if (parse_main_dynobj(filename)) return 3;
    main_link_map = get_link_map(filename);
    obj_link_map = main_link_map.l_next;

    while(obj_link_map)
    {
	aux_link_map = parse_lib_dynobj(obj_link_map);
	if (!aux_link_map) return 4;
	obj_link_map = aux_link_map->l_next;
    }

    for (o = target.dynobjs; o != NULL; o = o->next)
    {
	if (o->loop) addr.loop = o->loop;
	if (o->trigger) addr.trigger = o->trigger;
	if (o->path_buffer) addr.path_buffer = o->path_buffer;
        if (o->check) addr.check = o->check;
    }

    if (!(addr.loop && addr.trigger && addr.path_buffer))
    {
	WARN("error: ulp addresses not found.\n");
	return 5;
    }

    return 0;
}

int hijack_threads()
{
    struct ulp_thread *t;
    struct user_regs_struct context;

    if (!addr.loop) {
	WARN("error: loop not found.");
	return 1;
    }

    for (t = target.threads; t != NULL; t = t->next)
    {
	if (attach(t->tid))
	{
	    WARN("Hijack %d failed (attach).", t->tid);
	    return 2;
	};

	if (get_regs(t->tid, &t->context))
	{
	    WARN("Hijack %d failed (get_regs).", t->tid);
	    detach(t->tid);
	    return 3;
	};

	context = t->context;
	context.rip = addr.loop + 2;

	if (set_regs(t->tid, &context))
	{
	    WARN("Hijack %d failed (set_regs).", t->tid);
	    detach (t->tid);
	    return 4;
	};

	if (detach(t->tid))
	{
	    WARN("Hijack %d failed (detach).", t->tid);
	    return 5;
	};
    }

    return 0;
}

int set_id_buffer(char *patch_id, struct ulp_thread *t)
{
    struct user_regs_struct context;
    Elf64_Addr path_addr;
    int i;

    context = t->context;
    context.rip = addr.path_buffer + 2;

    if (run_and_redirect(t->tid, &context, addr.loop))
    {
	WARN("set_path_buffer error 1.");
	return 1;
    };

    path_addr = context.rax;
    // ADD CHECK HERE (ALSO FOR SET_PATH_BUFFER) TODO

    for (i = 0; i < 32; i++)
    {
      if (write_byte(patch_id[i], t->tid, path_addr + i))
      {
        WARN("Unable to write id byte %d.", i);
        return 2;
      }
    }

    return 0;
}


int set_path_buffer(char *path, struct ulp_thread *t)
{
    struct user_regs_struct context;
    Elf64_Addr path_addr;
    long int aux;

    context = t->context;
    context.rip = addr.path_buffer + 2;

    if (run_and_redirect(t->tid, &context, addr.loop))
    {
	WARN("set_path_buffer error 1.");
	return 1;
    };

    path_addr = context.rax;

    if (write_string(path, t->tid, path_addr))
    {
	WARN("set_path_buffer error 2.");
	return 2;
    }

    return 0;
}

int check_thread_consistency(char *path)
{
    struct user_regs_struct context;
    struct ulp_thread *t;
    struct ulp_object *obj;
    struct ulp_dynobj *d;
    int consistency;
    int aux;
    int path_buffer_set = 0;
    int test;

    if (!addr.loop) {
	WARN("error: consistency or loop not found.");
	return 1;
    }

    obj = ulp.objs;
    if (!obj->name)
    {
	WARN("object has no name\n");
	return 2;
    };

    for (d = target.dynobjs; d != NULL; d = d->next)
    {
	if (strcmp(d->filename, obj->name)==0) break;
    }

    if (d == NULL)
    {
	WARN("to be patched object (%s) not loaded.\n", obj->name);
	return 3;
    }

    for (t = target.threads; t != NULL; t = t->next)
    {
	context = t->context;
	context.rip = d->consistency + 2;

	if (run_and_redirect(t->tid, &context, addr.loop))
	{
	    WARN("unable to check consistency.");
	    return 4;
	}
	if (context.rax == 0) t->consistent = 1;
    }

    /* write path buffer */
    t = target.threads;
    if (set_path_buffer(path, t)) return 5;

    return 0;
}

int restore_threads()
{
    struct ulp_thread *t;
    struct user_regs_struct context, main_ctx;

    for (t = target.threads; t != NULL; t = t->next)
    {
	if (attach(t->tid))
	{
	    WARN("Restore threads error (can't attach).");
	    return 1;
	};
	if (set_regs(t->tid, &t->context))
	{
	    WARN("Restore threads error (can't set regs).");
	    return 2;
	};
	if (detach(t->tid))
	{
	    WARN("Restore threads error (can't detatch).");
	    return 3;
	};
    }

    return 0;
}

int check_consistency(char *path)
{
    struct ulp_thread *t;

    if (check_thread_consistency(path))
    {
	WARN("Unable to verify thread consistency.");
	return 1;
    };

    for (t = target.threads; t != NULL; t = t->next)
    {
	if (!t->consistent)
	{
	    WARN("Threads are not consistent.");
	    return 2;
	}
    }
    return 0;
}

int load_patch_info(char *livepatch)
{
    uint32_t c;
    int i, j;
    struct ulp_object *obj, *prev_obj;
    struct ulp_unit *unit, *prev_unit;
    struct ulp_dependency *dep, *prev_dep;
    FILE *file;


    file = fopen(livepatch, "rb");
    if (!file)
    {
	WARN("Unable to open metadata file: %s.", livepatch);
	return 1;
    }

    /* read metadata header information */
    ulp.objs = NULL;

    if (fread(&ulp.type, sizeof(uint8_t), 1, file) < 1)
    {
	WARN("Unable to read patch type.");
	return 2;
    }

    if (fread(&ulp.patch_id, sizeof(char), 32, file) < 32)
    {
	WARN("Unable to read patch id.");
	return 3;
    }

    if (fread(&c, sizeof(uint32_t), 1, file) < 1)
    {
	WARN("Unable to read so filename length.");
	return 4;
    }

    ulp.so_filename = calloc(c, sizeof(char));
    if (!ulp.so_filename)
    {
	WARN("Unable to allocate so filename buffer.");
	return 5;
    }

    if (fread(ulp.so_filename, sizeof(char), c, file) < c)
    {
	WARN("Unable to read so filename.");
	return 6;
    }

    obj = calloc(1, sizeof(struct ulp_object));
    if (!obj)
    {
	WARN("Unable to allocate memory for the patch objects.");
	return 7;
    }
    obj->units = NULL;

    if (fread(&c, sizeof(uint32_t), 1, file) < 1)
    {
	WARN("Unable to read build id length (trigger).");
	return 8;
    }
    obj->build_id_len = c;
    obj->build_id = calloc(c, sizeof(char));
    if (!obj->build_id)
    {
	WARN("Unable to allocate build id buffer.");
	return 9;
    }

    if (fread(obj->build_id, sizeof(char), c, file) < c)
    {
	WARN("Unable to read build id.");
	return 10;
    }

    obj->build_id_check = 0;

    if (fread(&c, sizeof(uint32_t), 1, file) < 1)
    {
	WARN("Unable to read object name length.");
	return 11;
    }

    /* shared object: fill data + read patching units */
    obj->name = calloc(c, sizeof(char));
    if (!obj->name)
    {
	WARN("Unable to allocate object name buffer.");
	return 12;
    }

    if (fread(obj->name, sizeof(char), c, file) < c)
    {
	WARN("Unable to read object name.");
	return 13;
    }

    if (fread(&obj->nunits, sizeof(uint32_t), 1, file) < 1)
    {
	WARN("Unable to read number of patching units.");
	return 14;
    }

    ulp.objs = obj;
    /* read all patching units for object */
    for (j = 0; j < obj->nunits; j++)
    {
	unit = calloc(1, sizeof(struct ulp_unit));
	if (!unit)
	{
	    WARN("Unable to allocate memory for the patch units.");
	    return 15;
	}

	if (fread(&c, sizeof(uint32_t), 1, file) < 1)
	{
	    WARN("Unable to read unit old function name length.");
	    return 16;
	}

	unit->old_fname = calloc(c, sizeof(char));
	if (!unit->old_fname)
	{
	    WARN("Unable to allocate unit old function name buffer.");
	    return 17;
	}

	if (fread(unit->old_fname, sizeof(char), c, file) < c)
	{
	    WARN("Unable to read unit old function name.");
	    return 18;
	}

	if (fread(&c, sizeof(uint32_t), 1, file) < 1)
	{
	    WARN("Unable to read unit new function name length.");
	    return 19;
	}

	unit->new_fname = calloc(c, sizeof(char));
	if (!unit->new_fname)
	{
	    WARN("Unable to allocate unit new function name buffer.");
	    return 20;
	}

	if (fread(unit->new_fname, sizeof(char), c, file) < c)
	{
	    WARN("Unable to read unit new function name.");
	    return 21;
	}

	if (fread(&unit->old_faddr, sizeof(void *), 1, file) < 1)
	{
	    WARN("Unable to read old function address.");
	    return 22;
	}

	if (obj->units)
	{
	    prev_unit->next = unit;
	} else {
	    obj->units = unit;
	}
	prev_unit = unit;
    }

    /* read dependencies */
    if (fread(&c, sizeof(uint32_t), 1, file) < 1)
    {
	WARN("Unable to read number of dependencies.");
	return 24;
    }

    for (i = 0; i < c; i++)
    {
	dep = calloc(1, sizeof(struct ulp_dependency));
	if (!dep)
	{
	    WARN("Unable to allocate memory for dependency state.");
	    return 25;
	}
	if (fread(&dep->dep_id, sizeof(char), 32, file) < 32)
	{
	    WARN("Unable to read dependency patch id.");
	    return 26;
	}
	if (ulp.deps)
	{
	    prev_dep->next = dep;
	} else {
	    ulp.deps = dep;
	}
	prev_dep = dep;
    }

    return 1;
}

int check_patch_sanity()
{
    struct ulp_object *obj;
    struct ulp_dynobj *d;

    /* check if ulp functions exist in main */
    if (!(addr.loop && addr.trigger && addr.path_buffer))
    {
	WARN("ulp functions not found in main object.");
	return 1;
    }

    /* check if to-be-patched objects exist */
    obj = ulp.objs;
    if (!obj->name)
    {
	WARN("to be patched object has no name.");
	return 2;
    }

    for (d = target.dynobjs; d != NULL; d = d->next)
    {
	if (strcmp(d->filename, obj->name)==0) break;
    }

    if (!d)
    {
	WARN("to be patched object (%s) not loaded.", obj->name);
	return 3;
    }

    /* check if to-be-patched objects support ulp */
    if (!d->consistency)
    {
	WARN("to be patched object does not support ulp.");
	return 4;
    }

    return 0;
}
