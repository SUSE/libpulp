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
#include <limits.h>
#include <dirent.h>
#include <bfd.h>
#include <stddef.h>
#include <fcntl.h>
#include <sys/user.h>
#include <unistd.h>

#include "ptrace.h"
#include "introspection.h"
#include "../../include/ulp_common.h"

struct ulp_metadata ulp;

int parse_file_symtab(struct ulp_dynobj *obj, char needed)
{
    bfd *file;
    int symtab_len;

    file = bfd_openr(obj->filename, NULL);
    if (!file)
    {
        if (needed) {
            WARN("bfd_openr error: %s.", obj->filename);
            return 1;
        }
        else return 0;
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

int dig_main_link_map(struct ulp_process *process)
{
    Elf64_Addr dyn_addr = 0, link_map, link_map_addr, r_debug = 0;
    int nentries, i, r_map_offset;
    ElfW(Dyn) dyn;
    asymbol **symtab;

    symtab = process->dynobj_main->symtab;
    nentries = process->dynobj_main->symtab_len;

    for (i = 0; i < nentries; i++) {
	if (strcmp(bfd_asymbol_name(symtab[i]),"_DYNAMIC")==0) {
	    dyn_addr = bfd_asymbol_value(symtab[i]);
	    break;
	}
    }
    /* fix for PIE executables */
    dyn_addr = dyn_addr + process->load_bias;

    if (i == nentries) {
	WARN("error parsing _DYNAMIC.");
	return 1;
    };

    while(1) {
	if (read_memory((char *) &dyn, sizeof(ElfW(Dyn)), process->pid,
			dyn_addr))
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

    if (read_memory((char *) &link_map, sizeof(void *), process->pid,
		    link_map_addr))
    {
	WARN("error reading link_map address.");
	return 4;
    }

    if (read_memory((char *) &process->dynobj_main->link_map,
		    sizeof(struct link_map), process->pid, link_map))
    {
	WARN("error reading link_map address.");
	return 5;
    }

    free(symtab);
    return 0;
}

int parse_threads(struct ulp_process *process)
{
    struct ulp_thread *t, *prev_t;
    char *format_str, *dirname;
    DIR *tasks_dir;
    struct dirent *dir;
    int tid;

    format_str = "/proc/%d/task/";
    dirname = calloc(strlen(format_str) + 10, 1);
    sprintf(dirname, format_str, process->pid);

    prev_t = NULL;

    tasks_dir = opendir(dirname);
    if (tasks_dir) {
	dir = readdir(tasks_dir);
	while (dir != NULL) {
	    tid = atoi(dir->d_name);
	    /* add main thread in front, after this loop */
	    if (!tid || tid == process->pid)
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
    t->tid = process->pid;
    t->next = prev_t;
    t->consistent = 0;
    process->threads = t;

    return 0;
}

Elf64_Addr get_loaded_symbol_addr(struct ulp_dynobj *obj, char *sym)
{
    int i;
    Elf64_Addr sym_addr, ptr = 0;

    for (i = 0; i < obj->symtab_len; i++) {
	if (strcmp(bfd_asymbol_name(obj->symtab[i]), sym)==0) {
	    ptr = bfd_asymbol_value(obj->symtab[i]);
	}
    }

    if (ptr == 0) return 0;

    sym_addr = ptr + obj->link_map.l_addr;

    return sym_addr;
}

int dig_load_bias(struct ulp_process *process)
{
    int auxv, i;
    char *format_str, *filename;
    Elf64_auxv_t at;
    uint64_t addrof_entry = 0;
    Elf64_Addr addrof_start = 0;
    struct ulp_dynobj *obj;

    obj = process->dynobj_main;

    if (!obj->symtab)
    {
	WARN("error: initialize process first.");
	return 1;
    }

    format_str = "/proc/%d/auxv";
    filename = calloc(strlen(format_str) + 10, 1);
    sprintf(filename, format_str, process->pid);

    auxv = open(filename, O_RDONLY);
    if (!auxv)
    {
	WARN("error: unable to open auxv.");
	return 2;
    }

    do {
	if (read(auxv, &at, sizeof(Elf64_auxv_t))
	    != sizeof(Elf64_auxv_t)) {
	    WARN("error: unable to read auxv.");
	    return 2;
	}
	if (at.a_type == AT_ENTRY) {
	    addrof_entry = at.a_un.a_val;
	    break;
	}
    } while (at.a_type != AT_NULL);
    if (addrof_entry == 0) {
	WARN("error: unable to find entry address for the executable");
	return 3;
    }

    for (i = 0; i < obj->symtab_len; i++) {
	if (strcmp(bfd_asymbol_name(obj->symtab[i]),"_start")==0) {
	    addrof_start = bfd_asymbol_value(obj->symtab[i]);
	    break;
	}
    }
    if (addrof_start == 0) {
	WARN("error: unable to find address for _start");
	return 4;
    }

    process->load_bias = addrof_entry - addrof_start;
    free(filename);
    return 0;
}

int parse_main_dynobj(struct ulp_process *process)
{
    struct ulp_dynobj *obj;
    /* calloc initializes all to zero */
    obj = calloc(sizeof(struct ulp_dynobj), 1);
    if (!obj)
    {
	WARN("Unable to allocate object structure.");
	return 1;
    }

    obj->filename = malloc (PATH_MAX);
    snprintf (obj->filename, PATH_MAX, "/proc/%d/exe", process->pid);

    if (parse_file_symtab(obj, 1)) return 2;
    obj->next = NULL;

    process->dynobj_main = obj;

    if (dig_load_bias(process)) return 3;
    if (dig_main_link_map(process)) return 4;

    return 0;
}

int parse_libs_dynobj(struct ulp_process *process)
{
  struct link_map *obj_link_map, *aux_link_map;

  /* Iterate over the link map to build the list of libraries. */
  obj_link_map = process->dynobj_main->link_map.l_next;
  while(obj_link_map)
  {
    aux_link_map = parse_lib_dynobj(process, obj_link_map);
    if (!aux_link_map) break;
    obj_link_map = aux_link_map->l_next;
  }

  /* When libulp has been loaded (usually with LD_PRELOAD),
   * parse_lib_dynobj will find the symbols it provides, such as
   * __ulp_loop, which are all required for userspace live-patching. If
   * libulp has not been found, process->dynobj_libulp will be NULL and
   * this function returns an error.
   */
  if (process->dynobj_libulp == NULL)
    return 1;

  return 0;
}

struct link_map *parse_lib_dynobj(struct ulp_process *process,
                                  struct link_map *link_map_addr)
{
    struct ulp_dynobj *obj;
    struct link_map *link_map;
    char needed = 0;
    char *libname;

    /* calloc initializes all to zero */
    obj = calloc(sizeof(struct ulp_dynobj), 1);
    link_map = calloc(sizeof(struct link_map), 1);

    if (read_memory((char *) link_map, sizeof(struct link_map),
		    process->pid, (Elf64_Addr) link_map_addr))
    {
	WARN("error reading link_map address.");
	return NULL;
    }

    libname = calloc(PATH_MAX, 1);
    if (read_string(&libname, process->pid,
                    (Elf64_Addr) link_map->l_name))
    {
	WARN("error reading link_map string.");
	return NULL;
    }

    if (libname[0] != '/') return link_map;

    obj->filename = libname;

    /* ensure that PIE was verified */
    if (!process->dynobj_main) return NULL;

    // We always need to parse the main object, the to-be-patched object and the
    // libpulp object. The first two can be found easily, but not the latter,
    // because paths can change.
    // We can't enforce all to be parsed, because some files may be moved, as
    // when we have a livepatch object loaded and the uninstalled. The "needed"
    // workaround enforces the first two to be patched, while allowing some
    // loaded objects to be bypassed. If libpulp is not this tool will cry later
    // about absence of a trigger reference. So, no big harm.
    if (ulp.objs && strcmp(ulp.objs->name, obj->filename)==0) needed = 1;
    if (parse_file_symtab(obj, needed)) return NULL;

    obj->link_map = *link_map;
    obj->trigger = get_loaded_symbol_addr(obj, "__ulp_trigger");
    obj->loop = get_loaded_symbol_addr(obj, "__ulp_loop");
    obj->path_buffer = get_loaded_symbol_addr(obj, "__ulp_get_path_buffer");
    obj->check = get_loaded_symbol_addr(obj, "__ulp_check_patched");
    obj->state = get_loaded_symbol_addr(obj, "__ulp_state");

    /* libulp must expose all these symbols. */
    if (obj->loop && obj->trigger && obj->path_buffer && obj->check &&
	obj->state) {
	obj->next = NULL;
	process->dynobj_libulp = obj;
    }
    /* No other library should expose these symbols. */
    else if (obj->loop || obj->trigger || obj->path_buffer ||
	     obj->check || obj->state)
	WARN("libulp symbol exposed by some other library.");
    /* All other libraries go into the generic list. */
    else {
	obj->next = process->dynobjs;
	process->dynobjs = obj;
    }

    return link_map;
}

int initialize_data_structures(struct ulp_process *process,
                               char *livepatch)
{
    if (!process)
      return 1;

    if (load_patch_info(livepatch))
    {
	WARN("Unable to load patch info.");
	return 1;
    }

    bfd_init();

    if (parse_threads(process)) return 2;

    if (parse_main_dynobj(process)) return 3;
    if (parse_libs_dynobj(process)) return 3;

    /* Check if libulp constructor has already been executed.  */
    struct ulp_patching_state ulp_state;
    if (read_memory((char *) &ulp_state, sizeof(ulp_state),
                    process->pid, process->dynobj_libulp->state)
        || ulp_state.load_state == 0) {
      return EAGAIN;
    }

    return 0;
}

int hijack_threads(struct ulp_process *process)
{
    struct ulp_thread *t;
    struct user_regs_struct context;

    if (!process->dynobj_libulp->loop) {
	WARN("error: loop not found.");
	return 1;
    }

    for (t = process->threads; t != NULL; t = t->next)
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
	context.rip = process->dynobj_libulp->loop + 2;

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

int set_id_buffer(struct ulp_process *process, unsigned char *patch_id)
{
    struct ulp_thread *thread;
    struct user_regs_struct context;
    Elf64_Addr path_addr;
    int i;

    thread = process->threads;
    context = thread->context;
    context.rip = process->dynobj_libulp->path_buffer + 2;

    if (run_and_redirect(thread->tid, &context,
			 process->dynobj_libulp->loop))
    {
	WARN("set_id_buffer error 1.");
	return 1;
    };

    path_addr = context.rax;
    // ADD CHECK HERE (ALSO FOR SET_PATH_BUFFER) TODO

    for (i = 0; i < 32; i++)
    {
      if (write_byte(patch_id[i], thread->tid, path_addr + i))
      {
        WARN("Unable to write id byte %d.", i);
        return 2;
      }
    }

    return 0;
}


int set_path_buffer(struct ulp_process *process, char *path)
{
    struct ulp_thread *thread;
    struct user_regs_struct context;
    Elf64_Addr path_addr;

    thread = process->threads;
    context = thread->context;
    context.rip = process->dynobj_libulp->path_buffer + 2;

    if (run_and_redirect(thread->tid, &context,
			 process->dynobj_libulp->loop))
    {
	WARN("set_path_buffer error 1.");
	return 1;
    };

    path_addr = context.rax;

    if (write_string(path, thread->tid, path_addr))
    {
	WARN("set_path_buffer error 2.");
	return 2;
    }

    return 0;
}

int restore_threads(struct ulp_process *process)
{
    struct ulp_thread *t;

    for (t = process->threads; t != NULL; t = t->next)
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

int load_patch_info(char *livepatch)
{
    uint32_t c;
    uint32_t i, j;
    struct ulp_object *obj;
    struct ulp_unit *unit, *prev_unit = NULL;
    struct ulp_dependency *dep, *prev_dep = NULL;
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

    ulp.so_filename = calloc(c + 1, sizeof(char));
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

    ulp.objs = obj;
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
    obj->name = calloc(c + 1, sizeof(char));
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

    if (ulp.type == 2) return 1;

    if (fread(&obj->nunits, sizeof(uint32_t), 1, file) < 1)
    {
	WARN("Unable to read number of patching units.");
	return 14;
    }


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

	unit->old_fname = calloc(c + 1, sizeof(char));
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

	unit->new_fname = calloc(c + 1, sizeof(char));
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

    return 0;
}

int check_patch_sanity(struct ulp_process *process)
{
    struct ulp_object *obj;
    struct ulp_dynobj *d;

    /* check if libulp, hence ulp functions, are loaded */
    if (!(process->dynobj_libulp))
    {
	WARN("libulp not loaded, thus ulp functions not available.");
	return 1;
    }

    /* check if to-be-patched objects exist */
    obj = ulp.objs;
    if (!obj->name)
    {
	WARN("to be patched object has no name.");
	return 2;
    }

    for (d = process->dynobjs; d != NULL; d = d->next)
    {
	if (strcmp(d->filename, obj->name)==0) break;
    }

    if (!d)
    {
	WARN("to be patched object (%s) not loaded.", obj->name);
	return 3;
    }

    return 0;
}
