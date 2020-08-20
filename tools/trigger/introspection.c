/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017-2020 SUSE Linux GmbH
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

/* Usage
 *
 * Information about live-patchable processes can be collected with the
 * help of a couple of functions from this introspection library.
 * Typically, an introspecting program will perform the following
 * operations:
 *
 *   1. (Optional) Initialize a livepatch object by reading a livepatch
 *      metadata file with load_patch_info();
 *   2. Allocate space for a ulp_process structure and set its pid
 *      member to the pid of the process it wants to instropect into
 *   3. Initialize this object by calling initialize_data_structures();
 *   4. (Optional) Verify, with check_patch_sanity(), that the livepatch
 *      and the process make sense together, i.e. that the livepatch is
 *      for a library that has been dynamically loaded by the process.
 *   5. Hijack the threads of the process with hijack_threads();
 *   6. Call one or more of the critical section routines:
 *        High-level routines:
 *          - apply_patch() to apply a live patch.
 *          - patch_applied() to verify if a live patch is applied.
 *          - read_global_universe() to read the global universe.
 *          - read_local_universes() to read all of the per-library,
 *            per-thread universes.
 *        Low-level routines (typically only used within this library):
 *          - set_id_buffer()
 *          - set_path_buffer()
 *   7. Restore the threads of the process with restore_threads();
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

#include "introspection.h"
#include "../../include/ulp_common.h"

struct ulp_metadata ulp;

/* Opens the file from which OBJ has been dynamically loaded and parses
 * its symtab (the parsed information gets stored in OBJ itself)
 * */
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

/* Parses the _DYNAMIC section of PROCESS, finds the DT_DEBUG entry,
 * from which the address of the chain of dynamically loaded objects
 * (link map) can be found, then reads it and stores it in PROCESS.
 */
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

/* Builds a list of the threads of PROCESS, which must have been
 * initialized with the pid of the desired process in PROCESS->pid.
 */
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

/* Looks for a symbol named SYM in OBJ. If the symbols gets found,
 * returns its address. Otherwise, returns 0.
 */
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

/* Calculates the load bias of PROCESS, i.e. the difference between the
 * adress of _start in the elf file and in memory. Returns 0 on success.
 */
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

/* Collects information about the main executable of PROCESS. Collected
 * information includes: the program symtab, load bias, and address of
 * the chain of loaded objects. On success, returns 0.
 */
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

/* Iterates over all objects that have been dynamically loaded into
 * PROCESS, parsing and sorting them into appropriate lists (for
 * instance, libpulp.so will be stored into PROCESS->dynobj_libpulp.
 * Returns 0, on success. If libpulp has not been found among the
 * dynamically loaded objects, returns 1.
 */
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

  /* When libpulp has been loaded (usually with LD_PRELOAD),
   * parse_lib_dynobj will find the symbols it provides, such as
   * __ulp_loop, which are all required for userspace live-patching. If
   * libpulp has not been found, process->dynobj_libpulp will be NULL and
   * this function returns an error.
   */
  if (process->dynobj_libpulp == NULL)
    return 1;

  return 0;
}

/* Attach into PROCESS, then reads the link_map structure pointed to by
 * LINK_MAP_ADDR, which contains information about a dynamically loaded
 * object, such as the name of the file from which it has been loaded.
 * Opens such file and parses its symtab to look for relevant symbols,
 * then, based on the symbols found, adds a new ulp_dynobj object into
 * the appropriate list in PROCESS.
 *
 * This function is supposed to be called multiple times, normally by
 * parse_libs_dynobj(), so that all objects that have been dynamically
 * loaded into PROCESS are parsed and sorted.
 *
 * On success, returns the link_map that has been read from the attached
 * PROCESS. Otherwise, returns NULL.
 */
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
    obj->global = get_loaded_symbol_addr(obj, "__ulp_get_global_universe");
    obj->local = get_loaded_symbol_addr(obj, "__ulp_get_local_universe");
    obj->testlocks = get_loaded_symbol_addr(obj, "__ulp_testlocks");

    /* libpulp must expose all these symbols. */
    if (obj->loop && obj->trigger && obj->path_buffer && obj->check &&
	obj->state && obj->global && obj->testlocks) {
	obj->next = NULL;
	process->dynobj_libpulp = obj;
    }
    /* No other library should expose these symbols. */
    else if (obj->loop || obj->trigger || obj->path_buffer ||
	     obj->check || obj->state || obj->global || obj->testlocks)
	WARN("libpulp symbol exposed by some other library.");
    /* Live-patchable libraries expose the local universe. */
    else if (obj->local) {
	obj->next = process->dynobj_targets;
	process->dynobj_targets = obj;
    }
    /* Live patch objects. */
    /* XXX: Searching for the '_livepatch' substring in the filename of
     * a dynamically loaded object is rather frail. Alternatives:
     *   A. Have live patch DSOs expose some predefined symbol.
     *   B. Have libpulp mmap a .ulp or .rev file into memory.
     */
    else if (strstr (obj->filename, "_livepatch")) {
	obj->next = process->dynobj_patches;
	process->dynobj_patches = obj;
    }
    /* All other libraries go into the generic list. */
    else {
	obj->next = process->dynobj_others;
	process->dynobj_others = obj;
    }

    return link_map;
}

/* Collects multiple pieces of information about PROCESS, so that it can
 * be introspected. Collected information includes: list of threads;
 * list of dynamically loaded objects, including the main executable;
 * and addresses of required symbols.
 *
 * PROCESS cannot be NULL and PROCESS->pid must have been previously
 * initialized with the pid of the desired process.
 *
 * On success, returns 0.
 */
int initialize_data_structures(struct ulp_process *process)
{
    if (!process)
      return 1;

    bfd_init();

    if (parse_threads(process)) return 2;

    if (parse_main_dynobj(process)) return 3;
    if (parse_libs_dynobj(process)) return 3;

    /* Check if libpulp constructor has already been executed.  */
    struct ulp_patching_state ulp_state;
    if (read_memory((char *) &ulp_state, sizeof(ulp_state),
                    process->pid, process->dynobj_libpulp->state)
        || ulp_state.load_state == 0) {
      return EAGAIN;
    }

    return 0;
}

/* Puts the threads in PROCESS into an infinite loop, so that other
 * introspection routines, e.g. set_id_buffer() and set_path_buffer(),
 * can be used. On success, returns 0.
 *
 * NOTE: this function marks the beginning of the critical section.
 */
int hijack_threads(struct ulp_process *process)
{
    int errors;
    struct ulp_thread *t;
    struct user_regs_struct context;

    if (!process->dynobj_libpulp->loop) {
	WARN("error: loop not found.");
	return 1;
    }

    if (stop(process->pid)) {
	WARN("Hijack prologue failed (stop).");
	return 1;
    }

    errors = 0;
    for (t = process->threads; t != NULL; t = t->next)
    {
	if (attach(t->tid))
	{
	    WARN("Hijack %d failed (attach).", t->tid);
	    errors = 1;
	    break;
	};

	if (get_regs(t->tid, &t->context))
	{
	    WARN("Hijack %d failed (get_regs).", t->tid);
	    detach(t->tid);
	    errors = 1;
	    break;
	};

	context = t->context;
	context.rip = process->dynobj_libpulp->loop + 2;

	if (set_regs(t->tid, &context))
	{
	    WARN("Hijack %d failed (set_regs).", t->tid);
	    detach (t->tid);
	    errors = 1;
	    break;
	};

	if (detach(t->tid))
	{
	    WARN("Hijack %d failed (detach).", t->tid);
	    errors = 1;
	    break;
	};
    }

    if (restart(process->pid)) {
	WARN("Hijack epilogue failed (restart).");
	return 1;
    }

    return errors;
}

/* Jacks into PROCESS and writes PATCH_ID into libpulp's
 * '__ulp_path_buffer'. This operation is a pre-condition to check if a
 * live patch is applied. On success, returns 0.
 *
 * WARNING: this function is in the critical section, so it can only be
 * called after successful thread hijacking.
 */
int set_id_buffer(struct ulp_process *process, unsigned char *patch_id)
{
    struct ulp_thread *thread;
    struct user_regs_struct context;
    Elf64_Addr path_addr;
    int i;

    thread = process->threads;
    context = thread->context;
    context.rip = process->dynobj_libpulp->path_buffer + 2;

    if (run_and_redirect(thread->tid, &context,
			 process->dynobj_libpulp->loop))
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

/* Jacks into PROCESS and writes PATH into libpulp's '__ulp_path_buffer'.
 * This operation is a pre-condition to apply a new live patch. On
 * success, returns 0.
 *
 * WARNING: this function is in the critical section, so it can only be
 * called after successful thread hijacking.
 */
int set_path_buffer(struct ulp_process *process, char *path)
{
    struct ulp_thread *thread;
    struct user_regs_struct context;
    Elf64_Addr path_addr;

    thread = process->threads;
    context = thread->context;
    context.rip = process->dynobj_libpulp->path_buffer + 2;

    if (run_and_redirect(thread->tid, &context,
			 process->dynobj_libpulp->loop))
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

/* Jacks into PROCESS and checks the conditions that are necessary to
 * safely call dlopen and calloc from a signal handler, even though
 * these are AS-Unsafe functions. The conditions are:
 *
 *   - All of the locks in the malloc implementation must be free,
 *     otherwise, a call to any of the functions from the malloc family
 *     could cause a deadlock.
 *
 *   - The locks in the dynamic linker implementation (dl_load_lock and
 *     dl_load_write_lock) must be free, otherwise, a call to any of the
 *     functions from the dlopen family could cause a deadlock.
 *
 * Checking the conditions above is accomplished by __ulp_do_testlocks.
 * See its implementation for more information.
 *
 * Returns 0 if the process, in its currently hijacked condition is able
 * to apply a live patch. Otherwise, returns 1, which means that
 * applying a live patch could result in a deadlock.
 *
 * WARNING: this function is in the critical section, so it can only be
 * called after successful thread hijacking.
 */
int testlocks(struct ulp_process *process)
{
    struct ulp_thread *thread;
    struct user_regs_struct context;

    thread = process->threads;
    context = thread->context;
    context.rip = process->dynobj_libpulp->testlocks + 2;

    if (run_and_redirect(thread->tid, &context,
			 process->dynobj_libpulp->loop))
    {
	WARN("error: unable to trig thread %d.", thread->tid);
	return 2;
    };

    return context.rax;
}

/* Jacks into PROCESS and checks if the live patch with PATCH_ID has
 * already been applied. Returns 1 if it has and 0 it if hasn't.
 * On error, returns 2.
 *
 * WARNING: this function is in the critical section, so it can only be
 * called after successful thread hijacking.
 */
int patch_applied(struct ulp_process *process, unsigned char *patch_id)
{
    struct ulp_thread *thread;
    struct user_regs_struct context;

    if (set_id_buffer(process, patch_id)) return 2;

    thread = process->threads;
    context = thread->context;
    context.rip = process->dynobj_libpulp->check + 2;

    if (run_and_redirect(thread->tid, &context,
			 process->dynobj_libpulp->loop))
    {
	WARN("error: unable to trig thread %d.", thread->tid);
	return 2;
    };

    return context.rax;
}

/* Jacks into PROCESS and installs the live patch pointed to by the
 * METADATA file. Returns 0 on success, and 1 otherwise.
 *
 * WARNING: this function is in the critical section, so it can only be
 * called after successful thread hijacking.
 */
int apply_patch(struct ulp_process *process, char *metadata)
{
    struct ulp_thread *thread;
    struct user_regs_struct context;

    if (set_path_buffer(process, metadata)) return 1;

    thread = process->threads;
    context = thread->context;
    context.rip = process->dynobj_libpulp->trigger + 2;

    if (run_and_redirect(thread->tid, &context,
			 process->dynobj_libpulp->loop))
    {
	WARN("error: unable to trig thread %d.", thread->tid);
	return 1;
    };

    if (!context.rax)
    {
	WARN("apply patch error: patch not applied.");
	return 1;
    }

    return 0;
}

/* Reads the global universe counter in PROCESS. Returns the
 * non-negative integer corresponding to the counter, or -1 on error.
 */
int read_global_universe (struct ulp_process *process)
{
    struct ulp_thread *thread;
    struct user_regs_struct context;

    thread = process->threads;
    context = thread->context;
    context.rip = process->dynobj_libpulp->global + 2;

    if (run_and_redirect(thread->tid, &context,
                         process->dynobj_libpulp->loop))
    {
        WARN("error: unable to read global universe from thread %d.",
             thread->tid);
        return -1;
    };

    process->global_universe = context.rax;
    return 0;
}

/* Returns the local universe counter for the THREAD-LIBRARY pair in
 * PROCESS. The return value does not distinguish between successfull
 * and erroneous reads, although an error messages gets printed.
 */
unsigned long read_local_universe (struct ulp_process *process,
                                   struct ulp_dynobj *library,
                                   struct ulp_thread *thread)
{
    struct user_regs_struct context;

    context = thread->context;
    context.rip = library->local + 2;

    if (run_and_redirect(thread->tid, &context,
                         process->dynobj_libpulp->loop))
      WARN("error: unable to read local universe from thread %d.",
           thread->tid);

    return context.rax;
}

/* For each pair of library and thread in PROCESS, reads its
 * per-library, per-thread universe counter (only libraries that are
 * live patchable are taken into account). Always returns 0.
 */
int read_local_universes (struct ulp_process *process)
{
  struct ulp_dynobj *library;
  struct ulp_thread *thread;
  struct thread_state *state;

  library = process->dynobj_targets;
  while (library) {
    library->thread_states = NULL;
    thread = process->threads;
    while (thread) {
      state = malloc (sizeof (struct thread_state));
      state->tid = thread->tid;
      state->universe = read_local_universe (process, library, thread);
      state->next = library->thread_states;
      library->thread_states = state;
      thread = thread->next;
    }
    library = library->next;
  }
  return 0;
}

/* Restores the threads in PROCESS to their normal state, i.e. removes
 * them from the infinite loop, into which they have been put by a
 * previous call to hijack_threads(). On success, returns 0.
 *
 * NOTE: this function marks the end of the critical section.
 */
int restore_threads(struct ulp_process *process)
{
    int errors;
    struct ulp_thread *t;

    if (!process->dynobj_libpulp->loop) {
	WARN("error: loop not found.");
	return 1;
    }

    if (stop(process->pid)) {
	WARN("Hijack prologue failed (stop).");
	return 1;
    }

    errors = 0;
    for (t = process->threads; t != NULL; t = t->next)
    {
	if (attach(t->tid))
	{
	    WARN("Restore threads error (can't attach).");
	    errors = 1;
            break;
	};
	if (set_regs(t->tid, &t->context))
	{
	    WARN("Restore threads error (can't set regs).");
	    errors = 1;
            break;
	};
	if (detach(t->tid))
	{
	    WARN("Restore threads error (can't detatch).");
	    errors = 1;
            break;
	};
    }

    if (restart(process->pid)) {
	WARN("Hijack epilogue failed (restart).");
	return 1;
    }

    return errors;
}

/* Takes LIVEPATCH as a path to a livepatch metadata file, opens it,
 * parses the data, and fills the global variable 'ulp'. On Success,
 * returns 0.
 */
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

/* Checks if the livepatch parsed into the global variable 'ulp' is
 * suitable to be applied to PROCESS. Returns 0 if it is. Otherwise,
 * prints warning messages and returns any other integer.
 *
 * Before calling this function, the global variable 'ulp' should have
 * been initialized, typically by calling load_patch_info().
 */
int check_patch_sanity(struct ulp_process *process)
{
    struct ulp_object *obj;
    struct ulp_dynobj *d;

    /* check if libpulp, hence ulp functions, are loaded */
    if (!(process->dynobj_libpulp))
    {
	WARN("libpulp not loaded, thus ulp functions not available.");
	return 1;
    }

    /* check if to-be-patched objects exist */
    obj = ulp.objs;
    if (!obj->name)
    {
	WARN("to be patched object has no name.");
	return 2;
    }

    /* check if the affected library is present in the process. */
    for (d = process->dynobj_targets; d != NULL; d = d->next)
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
