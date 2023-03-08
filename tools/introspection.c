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
 *        Low-level routines (typically only used within this library):
 *          - set_id_buffer()
 *          - set_path_buffer()
 *   7. Restore the threads of the process with restore_threads();
 */

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <limits.h>
#include <link.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
#include <unistd.h>

#include "config.h"
#include "elf-extra.h"
#include "error_common.h"
#include "introspection.h"
#include "packer.h"
#include "ulp_common.h"

#if defined ENABLE_STACK_CHECK && ENABLE_STACK_CHECK
#include <libunwind-ptrace.h>
#endif

struct ulp_metadata ulp;
int ulp_verbose;
int ulp_quiet;

/** If this flag is enabled, ulp should not print colored messages.  */
bool no_color;

void
ulp_warn(const char *format, ...)
{
  if (!ulp_quiet) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
  }
}

void
ulp_debug(const char *format, ...)
{
  if (ulp_verbose) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
  }
}

static void
debug_ulp_unit(struct ulp_unit *unit)
{
  if (!unit)
    return;

  DEBUG("");
  DEBUG("  unit->old_fname: %s", unit->old_fname);
  DEBUG("  unit->new_fname: %s", unit->new_fname);
  DEBUG("  unit->old_faddr: %lx", (unsigned long)unit->old_faddr);
  DEBUG("  unit->next: %lx", (unsigned long)unit->next);
  DEBUG("");

  debug_ulp_unit(unit->next);
}

void
debug_ulp_object(struct ulp_object *obj)
{
  DEBUG("");
  DEBUG("obj: %lx", (unsigned long)obj);
  DEBUG("obj->build_id_len: %u", obj->build_id_len);
  DEBUG("obj->build_id_check: %u", obj->build_id_check);
  DEBUG("obj->build id: %lx", (unsigned long)obj->build_id);
  DEBUG("obj->name: %s", obj->name);
  DEBUG("obj->flags: %lx", (unsigned long)obj->flag);
  DEBUG("obj->nunits: %u", obj->nunits);
  DEBUG("obj->units: %lx", (unsigned long)obj->units);
  DEBUG("");

  debug_ulp_unit(obj->units);
}

void
debug_ulp_dynobj(struct ulp_dynobj *obj)
{
  WARN("");
  WARN("obj->filename = %s", obj->filename);
  WARN("obj->num_symbols = %d", obj->num_symbols);
  WARN("obj->dynsym_addr = %lx", obj->dynsym_addr);
  WARN("obj->dynstr_addr = %lx", obj->dynstr_addr);
  WARN("obj->dynstr_addr = %lx", obj->dynstr_addr);
  WARN("obj->trigger = %lx", obj->trigger);
  WARN("obj->check = %lx", obj->check);
  WARN("obj->state = %lx", obj->state);
  WARN("obj->global = %lx", obj->global);
  WARN("obj->revert_all = %lx", obj->revert_all);
  WARN("obj->metadata_buffer = %lx", obj->metadata_buffer);
  WARN("obj->error_state = %lx", obj->error_state);
  WARN("obj->enable_disable_patching = %lx", obj->enable_disable_patching);
}

/** @brief Release memory of an ulp_thread `t`
 *
 *  Release memory of an ulp_thread allocated with malloc as well as
 *  every field associated with it.
 *
 * @param p An ulp_thread structure.
 */
static void
release_ulp_thread(struct ulp_thread *t)
{
  struct ulp_thread *nextt;

  for (; t != NULL; t = nextt) {
    nextt = t->next;
    free(t);
  }
}

/** @brief Release memory of an ulp_dynobj `obj`
 *
 *  Release memory of an ulp_dynobj allocated with malloc as well as
 *  every field associated with it.
 *
 * @param p An ulp_dynobj structure.
 */
static void
release_ulp_dynobj(struct ulp_dynobj *obj)
{
  struct ulp_dynobj *nexto;

  for (; obj != NULL; obj = nexto) {
    nexto = obj->next;

    if (obj->filename) {
      free(obj->filename);
    }
    if (obj->thread_states)
      free(obj->thread_states);
    free(obj);
  }
}

void
release_trigger_results(struct trigger_results *list)
{
  if (list == NULL)
    return;

  release_trigger_results(list->next);
  free((void *)list->patch_name);
  free(list);
}

/** @brief Release memory of an ulp_process `p`
 *
 *  Release memory of an ulp_process allocated with malloc as well as
 *  every field associated with it.
 *
 * @param p An ulp_process structure
 */
void
release_ulp_process(struct ulp_process *p)
{
  struct ulp_process *nextp;

  for (; p != NULL; p = nextp) {
    nextp = p->next;

    release_ulp_thread(p->threads);
    release_ulp_dynobj(p->dynobj_main);
    release_ulp_dynobj(p->dynobj_targets);
    /* p->dynobj_libpulp don't require free as it is in targets chain.  */
    release_ulp_dynobj(p->dynobj_patches);
    release_trigger_results(p->results);
    free(p);
  }
}

/** @brief Release memory of an ulp_unit `unit`
 *
 *  Release memory of an ulp_unit allocated with malloc as well as
 *  every field associated with it.
 *
 * @param unit An ulp_unit structure.
 */
void
release_ulp_unit(struct ulp_unit *unit)
{
  if (!unit)
    return;

  FREE_AND_NULLIFY(unit->old_fname);
  FREE_AND_NULLIFY(unit->new_fname);
  release_ulp_unit(unit->next);
  free(unit);
}

/** @brief Release memory of an ulp_object `obj`
 *
 *  Release memory of an ulp_object allocated with malloc as well as
 *  every field associated with it.
 *
 * @param obj An ulp_object structure.
 */
void
release_ulp_object(struct ulp_object *obj)
{
  if (!obj)
    return;

  FREE_AND_NULLIFY(obj->build_id);
  FREE_AND_NULLIFY(obj->name);

  release_ulp_unit(obj->units);
  free(obj);
}

/** @brief Release memory of an ulp_dependency `dep`.
 *
 *  Release memory of an ulp_dependency allocated with malloc as well as
 *  every field associated with it.
 *
 * @param dep An ulp_dependency structure.
 */
void
release_ulp_dependency(struct ulp_dependency *dep)
{
  if (!dep)
    return;

  release_ulp_dependency(dep->next);
  FREE_AND_NULLIFY(dep);
}

/** @brief Release memory of an ulp_reference `ref`.
 *
 *  Release memory of an ulp_reference allocated with malloc as well as
 *  every field associated with it.
 *
 * @param ref An ulp_reference structure.
 */
void
release_ulp_reference(struct ulp_reference *ref)
{
  if (!ref)
    return;

  release_ulp_reference(ref->next);

  FREE_AND_NULLIFY(ref->target_name);
  FREE_AND_NULLIFY(ref->reference_name);
  FREE_AND_NULLIFY(ref);
}

/** @brief Release memory of the global structure `ulp`.
 *
 *  Release memory of the global `ulp_metadata` object allocated with
 *  malloc as well as every field associated with it.
 */
void
release_ulp_global_metadata(void)
{
  struct ulp_metadata *meta = &ulp;

  FREE_AND_NULLIFY(meta->so_filename);
  release_ulp_object(meta->objs);
  release_ulp_dependency(meta->deps);
  release_ulp_reference(meta->refs);

  memset(meta, 0, sizeof(struct ulp_metadata));
}

/** @brief Get first dynobj in the dynobj process chain
 *
 *  @return The first dynobj in process.
 */
struct ulp_dynobj *
dynobj_first(struct ulp_process *process)
{
  return process->dynobj_main;
}

/** @brief Get the next dynobj in the dynobj process chain
 *
 *  @return The next dynobj in process.
 */
struct ulp_dynobj *
dynobj_next(struct ulp_process *process, struct ulp_dynobj *curr_obj)
{
  if (curr_obj == process->dynobj_main) {
    return process->dynobj_targets;
  }
  else {
    return curr_obj->next;
  }
}

/* Parses the _DYNAMIC section of PROCESS, finds the DT_DEBUG entry,
 * from which the address of the chain of dynamically loaded objects
 * (link map) can be found, then reads it and stores it in PROCESS.
 */
int
dig_main_link_map(struct ulp_process *process)
{
  Elf64_Addr dyn_addr = 0, link_map, link_map_addr, r_debug = 0;
  int r_map_offset;
  ElfW(Dyn) dyn;

  dyn_addr = process->dyn_addr;

  while (1) {
    if (read_memory((char *)&dyn, sizeof(ElfW(Dyn)), process->pid, dyn_addr)) {
      DEBUG("error reading _DYNAMIC array.");
      return ETARGETHOOK;
    }
    if (dyn.d_tag == DT_NULL) {
      DEBUG("error searching for r_debug.");
      return ENODEBUGTAG;
    }
    if (dyn.d_tag == DT_DEBUG) {
      r_debug = dyn.d_un.d_ptr;
      break;
    }
    dyn_addr = dyn_addr + sizeof(ElfW(Dyn));
  }
  r_map_offset = offsetof(struct r_debug, r_map);
  link_map_addr = r_debug + r_map_offset;

  if (read_memory((char *)&link_map, sizeof(void *), process->pid,
                  link_map_addr)) {
    DEBUG("error reading link_map address.");
    return ETARGETHOOK;
  }

  if (read_memory((char *)&process->dynobj_main->link_map,
                  sizeof(struct link_map), process->pid, link_map)) {
    DEBUG("error reading link_map data.");
    return ETARGETHOOK;
  }

  return 0;
}

/* Get symbol by its name, but with extra complexity of reading it in a remote
 * process.
 */
static ElfW(Addr)
    get_symbol_by_name(int pid, ElfW(Addr) dynsym_addr, ElfW(Addr) dynstr_addr,
                       int len, const char *name)
{
  int i, ret;
  for (i = 0; i < len; i++) {
    ElfW(Sym) sym;
    char *remote_name;

    ret = read_memory((char *)&sym, sizeof(sym), pid, dynsym_addr);
    if (ret) {
      WARN("Unable to read dynamic symbol");
      /* Exit point 1: Either memory was not allocated or released by (*).  */
      return 0;
    }

    /* WARNING: remote name has to be released.  */
    ret = read_string(&remote_name, pid, dynstr_addr + sym.st_name);
    if (ret) {
      WARN("Unable to read dynamic symbol name");
      /* Exit point 2: Memory may leak in case of error when detaching.  */
      return 0;
    }

    if (!strcmp(remote_name, name)) {
      free(remote_name);
      /* Exit point 3: memory released in previous line.  */
      return sym.st_value;
    }

    dynsym_addr += sizeof(sym);
    free(remote_name); /* (*).  */
  }

  /* Exit point 4: memory released by (*).  */
  return 0;
}

#ifdef ENABLE_DLINFO_CACHE
static struct ulp_dynobj *
get_dynobj_by_bias(struct ulp_process *p, ElfW(Addr) bias)
{
  struct ulp_dynobj *d;
  for (d = dynobj_first(p); d != NULL; d = dynobj_next(p, d)) {
    if (d->link_map.l_addr == bias) {
      return d;
    }
  }

  return NULL;
}

int
get_dynobj_elf_by_cache(struct ulp_process *process)
{
  if (!process->dynobj_libpulp)
    return 1;

  if (!process->dynobj_libpulp->dlinfo_cache)
    return 1;

  pid_t pid = process->pid;
  struct ulp_dlinfo_cache dlinfo_cache;
  Elf64_Addr remote_dlinfo_cache;

  if (read_memory(&remote_dlinfo_cache, sizeof(Elf64_Addr), pid,
                  process->dynobj_libpulp->dlinfo_cache)) {
    return 1;
  }

  if (remote_dlinfo_cache == 0) {
    /* No remote cache.  */
    return 1;
  }

  while (remote_dlinfo_cache) {
    if (read_memory(&dlinfo_cache, sizeof(dlinfo_cache), pid,
                    remote_dlinfo_cache)) {
      return 1;
    }
    struct ulp_dynobj *obj = get_dynobj_by_bias(process, dlinfo_cache.bias);

    if (obj) {
      obj->dynsym_addr = dlinfo_cache.dynsym;
      obj->dynstr_addr = dlinfo_cache.dynstr;
      obj->num_symbols = dlinfo_cache.num_symbols;
      memcpy(obj->build_id, dlinfo_cache.buildid, BUILDID_LEN);
    }

    remote_dlinfo_cache = (Elf64_Addr)dlinfo_cache.next;
  }

  return 0;
}
#endif // ENABLE_DLINFO_CACHE

/** @brief Parses ELF headers of dynobj `obj` from process with pid `pid`.
 *
 * This function read the remote process memory to locate the following
 * information in the process, contained in the ELF header:
 *
 * - The `dynsym` section, where externally visible symbols are located.
 * - The `dynstr` section, where externally visible symbols name are located.
 * - The `hash` section, which holds the number of externally symbols.
 * - The `note` section, which holds the build-id of the library/program.
 *
 * @param pid Program ID of the process.
 * @param obj Object representing a library, or the main program itself.
 *
 * @return 0 on success, anything else on failure.
 */
int
parse_dynobj_elf_headers(int pid, struct ulp_dynobj *obj)
{
  ElfW(Addr) ehdr_addr = 0;
  ElfW(Ehdr) ehdr;
  ElfW(Addr) phdr_addr = 0;

  ElfW(Addr) dynsym_addr = 0;
  ElfW(Addr) dynstr_addr = 0;
  ElfW(Addr) hash_addr = 0;

  ElfW(Addr) buildid_addr = 0;

  ElfW(Word) name_len = 0;
  ElfW(Word) buildid_len = 0;

  int i, num_symbols = 0, ret;

  bool pt_dynamic_ran = false;
  bool pt_note_ran = false;

  /* If object has no link map attached to it, there is nothing we can do.  */
  if (!obj->link_map.l_name) {
    DEBUG("no link map object found");
    return ENOLINKMAP;
  }

  /* l_addr holds the pointer to the ELF header.  */
  ehdr_addr = obj->link_map.l_addr;

  /* Read ELF header from remote process.  */
  if (ehdr_addr == 0) {
    /* If l_addr is zero, it means that there is no load bias.  In that case,
     * the elf address is on address 0x400000 on x86_64.  */
    ret = read_memory((char *)&ehdr, sizeof(ehdr), pid, 0x400000UL);
  }
  else {
    ret = read_memory((char *)&ehdr, sizeof(ehdr), pid, ehdr_addr);
  }
  if (ret != 0) {
    DEBUG("Unable to read ELF header from process %d\n", pid);
    return ETARGETHOOK;
  }

  /* Sanity check if process header size is valid.  */
  if (ehdr.e_phentsize != sizeof(ElfW(Phdr))) {
    DEBUG("Invalid phdr readed");
    return ENOPHDR;
  }

  /* Get first process header address.  */
  phdr_addr = ehdr_addr + ehdr.e_phoff;
  if (ehdr_addr == 0)
    phdr_addr += 0x400000UL;

  /* Iterate over each process header.  */
  for (i = 0; i < ehdr.e_phnum; i++) {
    ElfW(Phdr) phdr;
    ElfW(Addr) curr_phdr_addr = phdr_addr + i * sizeof(ElfW(Phdr));

    /* Get first process header from remote process.  */
    ret = read_memory((char *)&phdr, sizeof(phdr), pid, curr_phdr_addr);
    if (ret != 0) {
      DEBUG("Unable to read process header from process %d\n", pid);
      return ETARGETHOOK;
    }

    /* Look for the dynamic section.  */
    if (phdr.p_type == PT_DYNAMIC && !pt_dynamic_ran) {
      ElfW(Dyn) dyn;
      ElfW(Addr) dyn_addr = ehdr_addr + phdr.p_paddr;

      /* Iterate over each tag in this section.  */
      do {
        /* Get the dynamic symbol in remote process.  */
        ret = read_memory((char *)&dyn, sizeof(dyn), pid, dyn_addr);
        if (ret != 0) {
          DEBUG("Unable to read dynamic symbol from process %d\n", pid);
          return ETARGETHOOK;
        }

        switch (dyn.d_tag) {
          case DT_SYMTAB:
            dynsym_addr = dyn.d_un.d_ptr;
            break;

          case DT_STRTAB:
            dynstr_addr = dyn.d_un.d_ptr;
            break;

          case DT_SYMENT:
            /* This section stores the size of a symbol entry. So compare it
             * with the size of Elf64_Sym as a sanity check.  */
            if (dyn.d_un.d_val != sizeof(ElfW(Sym)))
              DEBUG("DT_SYMENT value of %s is unexpected", obj->filename);
            break;

          case DT_HASH:
            hash_addr = dyn.d_un.d_ptr;
            if (!hash_addr)
              DEBUG("hash section found, but is empty");
            break;
        }
        dyn_addr += sizeof(dyn);

        /* There is no point in continuing if we already found what we want. */
        if (dynsym_addr && dynstr_addr && hash_addr) {
          pt_dynamic_ran = true;
          break;
        }
      }
      while (dyn.d_tag != DT_NULL);
    }
    else if (phdr.p_type == PT_NOTE) {
      /* We are after the build id.  */

      ElfW(Addr) note_addr = ehdr_addr + phdr.p_paddr;
      unsigned sec_size = phdr.p_memsz;
      ElfW(Addr) note_addr_end = note_addr + sec_size;

      do {
        ElfW(Nhdr) note;

        /* Get the note section in remote process.  */
        ret = read_memory((char *)&note, sizeof(note), pid, note_addr);
        if (ret != 0) {
          DEBUG("Unable to read note header from process %d\n", pid);
          return ETARGETHOOK;
        }

        name_len = note.n_namesz;
        buildid_len = note.n_descsz;

        /* Align with the 4 bytes boundary.  */
        buildid_len += buildid_len % 4;
        name_len += name_len % 4;

        if (note.n_type == NT_GNU_BUILD_ID) {
          /* Build id note section found.  */
          buildid_addr = note_addr + sizeof(note) + name_len;
          pt_note_ran = true;
          break;
        }

        note_addr += buildid_len + name_len + 12;
      }
      while (note_addr < note_addr_end);
    }

    /* There is no point in continuing if we already found what we want.  */
    if (pt_dynamic_ran == true && pt_note_ran == true)
      break;
  }

  if (buildid_addr) {
    if (buildid_len == sizeof(obj->build_id)) {
      ret = read_memory((char *)obj->build_id, buildid_len, pid, buildid_addr);
      if (ret != 0) {
        DEBUG("Unable to read build id from target process %d", pid);
      }
    }
    else {
      DEBUG("build id length mismatch: expected %lu, got %d",
            sizeof(obj->build_id), buildid_len);
    }
  }
  else {
    DEBUG("build id length mismatch: expected %lu, got %d",
          sizeof(obj->build_id), buildid_len);
  }

  if (hash_addr) {
    /* Look at the hash section for the number of the symbols in the
     * symbol table.  This section structure in memory is:
     *
     * hash_t nbuckets;
     * hash_t nchains;
     * hash_t buckets[nbuckets];
     * hash_t chain[nchains];
     *
     * hash_t is either int32_t or int64_t according to the arch.
     * On x86_64 it is 32-bits.
     */

    /* Get nchains.  */
    ret = read_memory((char *)&num_symbols, sizeof(int), pid,
                      hash_addr + sizeof(int));
    if (ret != 0) {
      DEBUG("Unable to read hash table at %lx", (hash_addr + sizeof(int)));
      return ETARGETHOOK;
    }
  }
  else {
    DEBUG("hash table not found in %s", obj->filename);
  }

  /* Finally store found address to the dynobj object.  */
  obj->dynstr_addr = dynstr_addr;
  obj->dynsym_addr = dynsym_addr;
  obj->num_symbols = num_symbols;

  return 0;
}

/** @brief Looks for a symbol named `sym_name` in loaded object `obj`.
 *
 * This function searches for a loaded symbol in `obj` on the process with
 * `pid` with a sumbol name `sym_name`. For example, calling this function
 * with `sym_name = "printf"` on `obj` representing the libc will return the
 * address of printf that was loaded in memory.
 *
 * @param obj The dynamic object representing a library or the process' binary.
 * @param pid The pid of the process.
 * @param sym_name The name of the symbol to look for
 *
 * @return The address of the symbol on success. Otherwise, returns 0.
 */
Elf64_Addr
get_loaded_symbol_addr(struct ulp_dynobj *obj, int pid, const char *sym_name)
{
  /* l_addr holds the pointer to the ELF header.  */
  ElfW(Addr) ehdr_addr = obj->link_map.l_addr;

  ElfW(Addr) dynsym_addr = obj->dynsym_addr;
  ElfW(Addr) dynstr_addr = obj->dynstr_addr;
  int num_symbols = obj->num_symbols;

  ElfW(Addr) sym_addr;

  /* If, for some reason, parse_dynobj_elf_headers failed to locate
    `num_symbols`, `dynsym`, or `dynstr`, we can't continue.  */
  if (!dynsym_addr || !dynstr_addr || num_symbols <= 0)
    return 0;

  sym_addr =
      get_symbol_by_name(pid, dynsym_addr, dynstr_addr, num_symbols, sym_name);

  return sym_addr ? (ehdr_addr + sym_addr) : 0;
}

static int
get_libpulp_extern_symbols(struct ulp_dynobj *obj, int pid)
{
  /* l_addr holds the pointer to the ELF header.  */
  ElfW(Addr) ehdr_addr = obj->link_map.l_addr;

  ElfW(Addr) dynsym_addr = obj->dynsym_addr;
  ElfW(Addr) dynstr_addr = obj->dynstr_addr;
  int num_symbols = obj->num_symbols;

  int bitfield = 0;

  char remote_name[64];

  /* If, for some reason, parse_dynobj_elf_headers failed to locate
    `num_symbols`, `dynsym`, or `dynstr`, we can't continue.  */
  if (!dynsym_addr || !dynstr_addr || num_symbols <= 0)
    return 0;

  int i, ret;
  for (i = 0; i < num_symbols; i++) {
    ElfW(Sym) sym;

    /* Only read the part of the struct we need.  */
    ret = read_memory(&sym.st_name, sizeof(sym.st_name), pid,
                      dynsym_addr + offsetof(ElfW(Sym), st_name));

    if (ret) {
      WARN("Unable to read dynamic symbol");
      return 1;
    }

    /* Read first part of string.  We are reading from remote process, so reads
       are expensive.  */
    ret = read_memory(remote_name, 5, pid, dynstr_addr + sym.st_name);
    if (ret) {
      WARN("Unable to read dynamic symbol name");
      return 1;
    }

    if (!strncmp(remote_name, "__ulp", 5)) {

      /* Now read the rest of the string.  5 here comes from "__ulp" size,
       * without '\0'.  */
      ret = read_string_allocated(remote_name, 64, pid,
                                  dynstr_addr + sym.st_name + 5);
      if (ret) {
        WARN("Unable to read dynamic symbol name");
        return 1;
      }

      /* Read the entire struct now.  */
      ret = read_memory(&sym, sizeof(sym), pid, dynsym_addr);
      if (ret) {
        WARN("Unable to read dynamic symbol");
        return 1;
      }

      if (!strcmp(remote_name, "_trigger")) {
        obj->trigger = ehdr_addr + sym.st_value;
        bitfield |= (1 << 0);
      }
      else if (!strcmp(remote_name, "_check_patched")) {
        obj->check = ehdr_addr + sym.st_value;
        bitfield |= (1 << 1);
      }
      else if (!strcmp(remote_name, "_state")) {
        obj->state = ehdr_addr + sym.st_value;
        bitfield |= (1 << 2);
      }
      else if (!strcmp(remote_name, "_get_global_universe")) {
        obj->global = ehdr_addr + sym.st_value;
        bitfield |= (1 << 3);
      }
      else if (!strcmp(remote_name, "_msg_queue")) {
        obj->msg_queue = ehdr_addr + sym.st_value;
        bitfield |= (1 << 4);
      }
      else if (!strcmp(remote_name, "_revert_all")) {
        obj->revert_all = ehdr_addr + sym.st_value;
        bitfield |= (1 << 5);
      }
      else if (!strcmp(remote_name, "_metadata_buffer")) {
        obj->metadata_buffer = ehdr_addr + sym.st_value;
        bitfield |= (1 << 6);
      }
      else if (!strcmp(remote_name, "_error_state")) {
        obj->error_state = ehdr_addr + sym.st_value;
        bitfield |= (1 << 7);
      }
      else if (!strcmp(remote_name, "_enable_or_disable_patching")) {
        obj->enable_disable_patching = ehdr_addr + sym.st_value;
        bitfield |= (1 << 8);
      }
    }

    dynsym_addr += sizeof(sym);

    if (bitfield == 0x1FF)
      break;
  }

  return 0;
}

/* Same as get_loaded_symbol_addr, but use the file in disk instead of parsing
 * the in-memory content of the remote process. This have the advantage of
 * finding non-exported symbols whose names aren't loaded in the process, but
 * may be unsafe because the file could have been changed in meanwhile.
 */
Elf64_Addr
get_loaded_symbol_addr_from_disk(struct ulp_dynobj *obj, const char *sym)
{
  char *str;
  int i;
  int fd;
  int len;
  size_t shstrndx;
  Elf *elf;
  Elf_Scn *scn;
  Elf_Data *data;
  GElf_Shdr *shdr;
  ElfW(Sym) * symbol;
  ElfW(Addr) sym_addr;
  ElfW(Addr) ptr;

  /*
   * Open the file for reading. Failing is not necessarily critical,
   * because this function is called for every loaded DSO in the
   * process and libraries unrelated to the live-patch might have been
   * uninstalled. If a required library is missing, for instance
   * libpulp.so, checks elsewhere should detect the problem.
   */
  fd = open(obj->filename, O_RDONLY);
  if (fd == -1) {
    return 0;
  }

  /* Parse the file with libelf. */
  elf_version(EV_CURRENT);
  elf = elf_begin(fd, ELF_C_READ, NULL);
  if (elf == NULL) {
    WARN("elf_begin error (%s).", obj->filename);
    return 0;
  }

  /* Find the string table. */
  if (elf_getshdrstrndx(elf, &shstrndx)) {
    WARN("elf_getshdrstrndx error (%s).", obj->filename);
    return 0;
  }

  /* Iterate over the sections until .symtab is found. */
  scn = NULL;
  shdr = (GElf_Shdr *)malloc(sizeof(GElf_Shdr));
  while ((scn = elf_nextscn(elf, scn))) {
    if (gelf_getshdr(scn, shdr) == NULL) {
      WARN("elf_getshdr error (%s).", obj->filename);
      return 0;
    }
    str = elf_strptr(elf, shstrndx, shdr->sh_name);
    if (strcmp(str, ".symtab") == 0)
      break;
  }
  /* If the .symtab is not available, skip OBJ. */
  if (scn == NULL)
    return 0;

  /* Iterate over the data in the .symtab until SYMBOL is found. */
  len = shdr->sh_size / sizeof(ElfW(Sym));
  ptr = 0;
  for (i = 0; i < len; i++) {
    data = elf_getdata(scn, NULL);
    symbol = (ElfW(Sym) *)(data->d_buf + (i * sizeof(ElfW(Sym))));
    str = elf_strptr(elf, shdr->sh_link, symbol->st_name);
    if (strcmp(sym, str) == 0) {
      ptr = symbol->st_value;
      break;
    }
  }
  sym_addr = ptr + obj->link_map.l_addr;

  /* Release resources. */
  elf_end(elf);
  close(fd);

  if (ptr == 0)
    return 0;
  return sym_addr;
}

/* Calculates the load bias of PROCESS, i.e. the difference between the
 * adress of _start in the elf file and in memory. Returns 0 on success.
 */
int
dig_load_bias(struct ulp_process *process)
{
  int auxv, i;
  char *format_str, *filename;
  Elf64_auxv_t at;
  uint64_t addrof_entry = 0;
  uint64_t at_phdr = 0;
  uint64_t pt_phdr = 0;
  uint64_t adyn = 0;
  int phent = 0, phnum = 0;
  Elf64_Phdr phdr;

  format_str = "/proc/%d/auxv";
  filename = calloc(strlen(format_str) + 10, 1);
  sprintf(filename, format_str, process->pid);

  auxv = open(filename, O_RDONLY);
  if (!auxv) {
    DEBUG("error: unable to open auxv.");
    return ENOENT;
  }

  do {
    if (read(auxv, &at, sizeof(Elf64_auxv_t)) != sizeof(Elf64_auxv_t)) {
      DEBUG("error: unable to read auxv.");
      close(auxv);
      return errno;
    }
    if (at.a_type == AT_ENTRY) {
      addrof_entry = at.a_un.a_val;
    }
    else if (at.a_type == AT_PHDR) {
      at_phdr = at.a_un.a_val;
    }
    else if (at.a_type == AT_PHNUM) {
      phnum = at.a_un.a_val;
    }
    else if (at.a_type == AT_PHENT) {
      phent = at.a_un.a_val;
    }
  }
  while (at.a_type != AT_NULL);
  if (addrof_entry == 0) {
    DEBUG("error: unable to find entry address for the executable");
    close(auxv);
    return ENOPENTRY;
  }
  if (at_phdr == 0) {
    DEBUG("error: unable to find program header of target process");
    close(auxv);
    return ENOPHDR;
  }
  if (phent != sizeof(phdr)) {
    DEBUG("error: invalid PHDR size for target process (32 bit process?)");
    close(auxv);
    return ENOPHDR;
  }
  for (i = 0; i < phnum; i++) {
    if (read_memory((char *)&phdr, phent, process->pid, at_phdr + i * phent)) {
      DEBUG("error: unable to read PHDR entry");
      close(auxv);
      return ETARGETHOOK;
    }
    switch (phdr.p_type) {
      case PT_PHDR:
        pt_phdr = phdr.p_vaddr;
        break;
      case PT_DYNAMIC:
        adyn = phdr.p_vaddr;
        break;
    }
  }

  process->load_bias = 0;
  if (pt_phdr) {
    adyn += at_phdr - pt_phdr;
    process->load_bias = at_phdr - pt_phdr;
  }
  process->dyn_addr = adyn;

  free(filename);
  close(auxv);
  return 0;
}

/* Collects information about the main executable of PROCESS. Collected
 * information includes: the program symtab, load bias, and address of
 * the chain of loaded objects. On success, returns 0.
 */
int
parse_main_dynobj(struct ulp_process *process)
{
  struct ulp_dynobj *obj;
  ulp_error_t ret = 0;

  DEBUG("getting in-memory information about the main executable.");

  const char *target_binary_name = get_target_binary_name(process->pid);
  if (target_binary_name == NULL) {
    DEBUG("unable to find name of process with pid %d.", process->pid);
    return EINVAL;
  }

  /* calloc initializes all to zero */
  obj = calloc(sizeof(struct ulp_dynobj), 1);
  if (!obj) {
    DEBUG("unable to allocate memory.");
    return ENOMEM;
  }

  obj->filename = malloc(PATH_MAX);
  strcpy(obj->filename, target_binary_name);

  DEBUG("process name = %s, process pid = %d", obj->filename, process->pid);

  obj->next = NULL;

  process->dynobj_main = obj;

  ret = dig_load_bias(process);
  if (ret) {
    WARN("unable to calculate the load bias for the executable: %s\n",
         libpulp_strerror(ret));
    return ret;
  }

  ret = dig_main_link_map(process);
  if (ret) {
    WARN("unable to parse the mappings of objects in memory: %s\n",
         libpulp_strerror(ret));
    return ret;
  }

  parse_dynobj_elf_headers(process->pid, obj);

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
int
parse_lib_dynobj(struct ulp_dynobj *obj, struct ulp_process *process)
{
  char *libname = obj->filename;
  int pid = process->pid;

  DEBUG("reading in-memory information about %s.", libname);

  /* ensure that PIE was verified */
  if (!process->dynobj_main)
    return EUNKNOWN;

  /*
   * While parsing a DSO, see if it exports the symbols required by
   * live-patching. Most symbols will be provided by libpulp.so, and
   * some by the target library.
   */

  if (obj->num_symbols > 0 && obj->dynstr_addr > 0 && obj->dynsym_addr > 0)
    return 0;

  /* Pointers to linux-vdso.so are invalid, so skip this library.  */
  if (strcmp(obj->filename, "linux-vdso.so.1"))
    parse_dynobj_elf_headers(pid, obj);

  /* Only libpulp.so should have those symbols exported.  */
  if (strstr(libname, "libpulp.so")) {
    get_libpulp_extern_symbols(obj, pid);

    /* libpulp must expose all these symbols. */
    if (obj->trigger && obj->check && obj->state && obj->global &&
        obj->revert_all && obj->metadata_buffer) {
      process->dynobj_libpulp = obj;
      DEBUG("(libpulp found)");
    }
    /* No other library should expose these symbols. */
    else if (obj->trigger || obj->check || obj->state || obj->global ||
             obj->revert_all || obj->metadata_buffer)
      WARN("unexpected subset of libpulp symbols exposed by %s.", libname);
  }

  return 0;
}

struct link_map *
get_libname_dynobj(struct ulp_process *process, struct link_map *link_map_addr)
{
  struct ulp_dynobj *obj;
  char *libname;
  int pid = process->pid;

  /* calloc initializes all to zero */
  obj = calloc(sizeof(struct ulp_dynobj), 1);

  if (read_memory((char *)&obj->link_map, sizeof(struct link_map), pid,
                  (Elf64_Addr)link_map_addr)) {
    WARN("error reading link_map address.");
    return NULL;
  }

  if (read_string(&libname, pid, (Elf64_Addr)obj->link_map.l_name)) {
    WARN("error reading link_map string.");
    return NULL;
  }

  obj->filename = libname;

  obj->next = process->dynobj_targets;
  process->dynobj_targets = obj;

  if (strstr(libname, "libpulp.so")) {
    process->dynobj_libpulp = obj;
  }

  return &obj->link_map;
}

/* Iterates over all objects that have been dynamically loaded into
 * PROCESS, parsing and sorting them into appropriate lists (for
 * instance, libpulp.so will be stored into PROCESS->dynobj_libpulp.
 * Returns 0, on success. If libpulp has not been found among the
 * dynamically loaded objects, returns 1.
 */
int
parse_libs_dynobj(struct ulp_process *process)
{
  struct link_map *obj_link_map, *aux_link_map;

  DEBUG("getting in-memory information about shared libraries.");

  /* Iterate over the link map to build the list of libraries. */
  obj_link_map = process->dynobj_main->link_map.l_next;
  while (obj_link_map) {
    aux_link_map = get_libname_dynobj(process, obj_link_map);
    if (!aux_link_map)
      break;
    obj_link_map = aux_link_map->l_next;
  }

  /* When libpulp has been loaded (usually with LD_PRELOAD),
   * parse_lib_dynobj will find the symbols it provides, such as
   * __ulp_trigger, which are all required for userspace live-patching.
   * If libpulp has not been found, process->dynobj_libpulp will be NULL
   * and this function returns an error.
   */
  if (process->dynobj_libpulp == NULL) {
    DEBUG("libpulp not loaded, thus live patching not possible.");
    return ENOLIBPULP;
  }

  if (parse_lib_dynobj(process->dynobj_libpulp, process)) {
    DEBUG("libpulp not loaded, thus live patching not possible.");
    return ENOLIBPULP;
  }

  /* Iterate over the link map to build the list of libraries. */
  struct ulp_dynobj *obj;
  for (obj = process->dynobj_targets; obj != NULL; obj = obj->next) {
    if (obj != process->dynobj_libpulp) {
      if (parse_lib_dynobj(obj, process))
        break;
    }
  }

  return 0;
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
int
initialize_data_structures(struct ulp_process *process)
{
  ulp_error_t ret = 0;

  if (!process)
    return 1;

  DEBUG("getting in-memory information about process %d.", process->pid);

  if (attach(process->pid)) {
    DEBUG("Unable to attach to %d to read data.\n", process->pid);
    ret = 1;
    goto detach_process;
  }

  ret = parse_main_dynobj(process);
  if (ret) {
    WARN("unable to get in-memory information about the main executable: %s\n",
         libpulp_strerror(ret));
    ret = 1;
    goto detach_process;
  }

  ret = parse_libs_dynobj(process);
  if (ret) {
    WARN("unable to get in-memory information about shared libraries: %s\n",
         libpulp_strerror(ret));
    ret = 1;
    goto detach_process;
  }

  /* Check if libpulp constructor has already been executed.  */
  struct ulp_patching_state ulp_state;
  if (read_memory((char *)&ulp_state, sizeof(ulp_state), process->pid,
                  process->dynobj_libpulp->state) ||
      ulp_state.load_state == 0) {
    WARN("libpulp not ready (constructors not yet run). Try again later.");
    ret = EAGAIN;
    goto detach_process;
  }

detach_process:
  if (detach(process->pid)) {
    DEBUG("Unable to detach %d.\n", process->pid);
    return ret;
  }

  return ret;
}

/*
 * Searches for a thread structure with TID in a LIST of threads.
 * Returns a pointer to the thread, if found; NULL otherwise.
 */
struct ulp_thread *
search_thread(struct ulp_thread *list, int tid)
{
  while (list) {
    if (list->tid == tid)
      return list;
    list = list->next;
  }
  return NULL;
}

/*
 * Writes PATCH_ID into libpulp's '__ulp_path_buffer'. This operation is
 * a pre-condition to check if a live patch is applied. On success,
 * returns 0.
 */
int
set_id_buffer(struct ulp_process *process, unsigned char *patch_id)
{
  struct ulp_thread *thread;
  Elf64_Addr path_addr;

  DEBUG("advertising live patch ID to libpulp.");

  if (!process->all_threads_hijacked) {
    WARN("not all threads hijacked.");
    return EUNKNOWN;
  }

  thread = process->main_thread;
  path_addr = process->dynobj_libpulp->metadata_buffer;

  if (write_bytes(patch_id, 32, thread->tid, path_addr)) {
    WARN("Unable to write buildid at address %lx.", path_addr);
    return ETARGETHOOK;
  }

  return 0;
}

/** @brief Writes the metadata into libpulp's '__ulp_metadata_buffer'.
 *
 * This operation is a pre-condition to apply a new live patch.
 *
 * @param process   ulp_process object.
 * @param metadata  buffer containing metadata.
 * @param size      size of the metadata.
 * @return 0 on success, anything else on failure.
 */
static int
set_metadata_buffer(struct ulp_process *process, const void *metadata,
                    size_t size)
{
  const char *cmetadata = metadata;

  struct ulp_thread *thread;
  Elf64_Addr metadata_addr;

  if (size >= ULP_METADATA_BUF_LEN) {
    WARN("Metadata content too large.");
    return EOVERFLOW;
  }

  thread = process->main_thread;
  metadata_addr = process->dynobj_libpulp->metadata_buffer;

  if (write_bytes(cmetadata, size, thread->tid, metadata_addr)) {
    return EUNKNOWN;
  }

  return ENONE;
}

int
set_string_buffer(struct ulp_process *process, const char *string)
{
  return set_metadata_buffer(process, string, strlen(string) + 1);
}

/*
 * Attaches to all threads in PROCESS, which causes them to stop. After
 * that, other introspection routines, such as set_id_buffer() and
 * set_metadata_buffer(), can be used. On success, returns 0. If anything
 * goes wrong during hijacking, try to restore the original state of the
 * program; if that succeeds, return 1, and -1 otherwise.
 *
 * NOTE: this function marks the beginning of the critical section.
 */
int
hijack_threads(struct ulp_process *process)
{
  char taskname[PATH_MAX];
  int fatal;
  int loop;
  int pid;
  int tid;
  DIR *taskdir;
  struct dirent *dirent;
  struct ulp_thread *t;

  if (process->all_threads_hijacked) {
    WARN("trying to reenter critical section with all threads hijacked is "
         "unsupported.");
    return EUNKNOWN;
  }

  DEBUG("entering the critical section (process hijacking).");

  /* Open /proc/<pid>/task. */
  pid = process->pid;
  snprintf(taskname, PATH_MAX, "/proc/%d/task", pid);
  taskdir = opendir(taskname);
  if (taskdir == NULL) {
    WARN("error opening %s: %s.", taskname, strerror(errno));
    return errno;
  }

  fatal = 0;

  /*
   * Iterate over the threads in /proc/<pid>/task, attaching to each
   * of them. Perform this operation in loop until no new entries are
   * found to guarantee that threads created during iterations of the
   * inner loop are taken into account.
   */
  do {
    loop = 0;

    /* Start from updated directory listing. */
    rewinddir(taskdir);

    errno = 0;
    while ((dirent = readdir(taskdir)) != NULL) {

      /* Thread number */
      tid = atoi(dirent->d_name);
      if (tid == 0)
        continue;

      /* Check that the thread has not already been dealt with. */
      t = search_thread(process->threads, tid);

      if (t == NULL) {
        /* New thread detected, so set outer loop re-run. */
        loop = 1;

        /*
         * For each new thread:
         *   Allocate memory for a new entry in the list;
         *   Attach with ptrace, which stops the thread;
         *   Save all registers;
         *   Update the list.
         */
        t = calloc(sizeof(struct ulp_thread), 1);
        if (!t) {
          WARN("unable to allocate memory.");
          goto child_alloc_error;
        }
        if (attach(tid)) {
          WARN("unable to attach to %d.", tid);
          goto child_attach_error;
        }
        if (get_regs(tid, &t->context)) {
          WARN("unable to get registers from %d.", tid);
          goto child_getregs_error;
        };
        t->tid = tid;
        t->next = process->threads;
        process->threads = t;

        /* Save an extra pointer to the main thread. */
        if (!tid || tid == pid)
          process->main_thread = t;

        errno = 0;
        continue;

        /* Error paths for the hijacking of a child thread */
      child_getregs_error:
        detach(tid);
      child_attach_error:
        free(t);
      child_alloc_error:
        goto children_restore;
      }
    }

    /*
     * The inner loop is over when readdir returns NULL. On error,
     * errno is set accordingly, otherwise it is left untouched.
     */
    if (errno) {
      WARN("error reading from the task directory (%s): %s", taskname,
           strerror(errno));
      goto children_restore;
    }
  }
  while (loop);

  /* Release resources and return successfully */
  if (closedir(taskdir))
    WARN("error closing %s: %s", taskname, strerror(errno));
  process->all_threads_hijacked = true;
  return 0;

  /*
   * If hijacking any of the threads fails, detach from all, release
   * resources, and return with error.
   */
children_restore:
  while (process->threads) {
    if (detach(process->threads->tid)) {
      WARN("WARNING: detaching from thread %d failed.", process->threads->tid);
      fatal = 1;
    }
    t = process->threads;
    process->threads = process->threads->next;
    free(t);
  }

  if (closedir(taskdir))
    WARN("Closing %s failed: %s", taskname, strerror(errno));

  if (fatal)
    return ETHRDDETTACH;
  return ETHRDATTACH;
}

/*
 * Jacks into PROCESS and checks if the live patch with ID has already
 * been applied. On success, writes the result to RESULT and returns 0.
 * On error, returns 1, and leaves RESULT untouched.
 *
 * WARNING: this function is in the critical section, so it can only be
 * called after successful thread hijacking.
 */
int
patch_applied(struct ulp_process *process, unsigned char *id, int *result)
{
  int ret;
  struct ulp_thread *thread;
  struct user_regs_struct context;
  ElfW(Addr) routine;

  DEBUG("checking if live patch is already applied.");

  if (!process->all_threads_hijacked) {
    WARN("not all threads hijacked.");
    return EUNKNOWN;
  }

  if (set_id_buffer(process, id)) {
    WARN("unable to write live patch ID into target process memory.");
    return ETARGETHOOK;
  }

  thread = process->main_thread;
  context = thread->context;
  routine = process->dynobj_libpulp->check;

  DEBUG(">>> running libpulp functions within target process...");
  ret = run_and_redirect(thread->tid, &context, routine);
  if (ret != 0) {
    WARN("error during live patch status check: %s", libpulp_strerror(ret));
  }
  DEBUG(">>> done.");
  if (ret)
    return ret;

  *result = context.rax;
  return 0;
}

/*
 * Jacks into PROCESS and installs the live patch pointed to by the
 * METADATA file. Returns 0 on success; EAGAIN if live patching was
 * avoided due to the risk of a deadlock; 1 if a common error ocurred;
 * and -1 if a fatal error ocurred, which means that the target process
 * might have been put into an inconsistent state and should be
 * terminated.
 *
 * WARNING: this function is in the critical section, so it can only be
 * called after successful thread hijacking.
 */
int
apply_patch(struct ulp_process *process, void *metadata, size_t metadata_size)
{
  int ret;
  struct ulp_thread *thread;
  struct user_regs_struct context;
  ElfW(Addr) routine;

  struct ulp_dynobj *dynobj_libpulp = process->dynobj_libpulp;
  uintptr_t rax;

  DEBUG("beginning live patch application.");

  if (!process->all_threads_hijacked) {
    WARN("not all threads hijacked.");
    return EUNKNOWN;
  }

  if (set_metadata_buffer(process, metadata, metadata_size)) {
    WARN("unable to write live patch path into target process memory.");
    return ETARGETHOOK;
  }

  thread = process->main_thread;
  context = thread->context;
  routine = dynobj_libpulp->trigger;

  rax = context.rax;

  DEBUG(">>> running libpulp functions within target process...");
  ret = run_and_redirect(thread->tid, &context, routine);
  if (ret) {
    WARN("error during live patch application: %s",
         libpulp_strerror(context.rax));
  }
  DEBUG(">>> done.");
  if (ret)
    return ret;

  if (context.rax != 0) {
    if (context.rax == EAGAIN)
      DEBUG("patching failed in libpulp.so: libc/libdl locks were busy");
    else if (context.rax == rax) {
      /* If rax register is not changed in this process, it is evidence that
         the routine in libpulp.so wasn't executed by some reason.  */
      DEBUG("patching failed in libpulp.so: %s",
            libpulp_strerror(EHOOKNOTRUN));
      return EHOOKNOTRUN;
    }
    else
      DEBUG("patching failed in libpulp.so: %s",
            libpulp_strerror(context.rax));
  }

  return context.rax;
}

int
revert_patches_from_lib(struct ulp_process *process, const char *lib_name)
{
  int ret;
  struct ulp_thread *thread;
  struct user_regs_struct context;
  ElfW(Addr) routine;

  DEBUG("beginning patches removal.");

  /* In case the revert_library is set to target, then we must revert the
   * target library of the patch.  */
  if (!strcmp(lib_name, "target") && ulp.objs) {
    /* TODO: We only support one target library per patch.  If we want to
       expand this, this also has to be changed.  */
    lib_name = ulp.objs->name;
  }

  if (!process->all_threads_hijacked) {
    WARN("not all threads hijacked.");
    return EUNKNOWN;
  }

  if (set_string_buffer(process, lib_name)) {
    WARN("unable to write library name into target process memory.");
    return ETARGETHOOK;
  }

  thread = process->main_thread;
  context = thread->context;
  routine = process->dynobj_libpulp->revert_all;

  DEBUG(">>> running libpulp functions within target process...");
  ret = run_and_redirect(thread->tid, &context, routine);
  if (ret) {
    WARN("error during live patch revert: %s", libpulp_strerror(ret));
  }
  DEBUG(">>> done.");
  if (ret)
    return ret;

  if (context.rax != 0) {
    if (context.rax == EAGAIN)
      WARN("patches reverse-all failed in libpulp.so: libc/libdl locks were "
           "busy");
    else
      WARN("patches reverse-all failed in libpulp.so: %s",
           libpulp_strerror(context.rax));
  }

  return context.rax;
}

/* Reads the global universe counter in PROCESS. Returns the
 * non-negative integer corresponding to the counter, or -1 on error.
 */
int
read_global_universe(struct ulp_process *process)
{
  struct ulp_thread *thread;
  struct user_regs_struct context;
  ElfW(Addr) routine;

  if (!process->all_threads_hijacked) {
    WARN("not all threads hijacked.");
    return EUNKNOWN;
  }

  thread = process->main_thread;
  context = thread->context;
  routine = process->dynobj_libpulp->global;

  if (run_and_redirect(thread->tid, &context, routine)) {
    WARN("error: unable to read global universe from thread %d.", thread->tid);
    return -1;
  };

  process->global_universe = context.rax;
  return 0;
}

/*
 * Restores the threads in PROCESS to their normal state, i.e. restores
 * their context (registers), then detaches from them. On success,
 * returns 0.
 *
 * NOTE: this function marks the end of the critical section.
 */
int
restore_threads(struct ulp_process *process)
{
  int errors;
  struct ulp_thread *thread;

  DEBUG("exiting the critical section (process release).");
  process->all_threads_hijacked = false;

  /*
   * Restore the context of all threads, which might have been used to
   * run routines from libpulp, and detach from them.
   */
  errors = 0;
  while (process->threads) {
    thread = process->threads;
    if (set_regs(thread->tid, &thread->context)) {
      WARN("Restoring thread failed (set_regs).");
      errors = 1;
    }
    if (detach(thread->tid)) {
      WARN("WARNING: detaching from thread %d failed.", process->threads->tid);
      errors = 1;
    }
    process->threads = process->threads->next;
    free(thread);
  }

  return errors;
}

/** @brief Extract .ulp section from livepatch container .so
 *
 * Extract the content of the .ulp section within the livepatch container .so
 * file into a buffer passed by reference through `out`, and returns the size
 * of it.
 *
 * This function also injects the path to the livepatch container (.so) into
 * the extracted metadata file.
 *
 * @param livepatch  Path to livepatch container (.so)
 * @param revert     Extract the revert patch instead.
 * @param out        Buffer containing the .ulp section, passed by reference.
 * @param prefix     Optional argument which will be prepended to the final
 *                   patch path.
 *
 * @return Size of the metadata content.
 * */
size_t
extract_ulp_from_so_to_mem(const char *livepatch, bool revert, char **out,
                           const char *prefix)
{
  int fd;
  const char *section = revert ? ".ulp.rev" : ".ulp";
  char path_buffer[2 * PATH_MAX];

  Elf *elf = load_elf(livepatch, &fd);
  if (elf == NULL) {
    *out = NULL;
    return 0;
  }

  Elf_Scn *ulp_scn = get_elfscn_by_name(elf, section);
  if (ulp_scn == NULL) {
    DEBUG("Unable to get section .ulp from elf %s: %s", livepatch,
          elf_errmsg(-1));
    unload_elf(&elf, &fd);
    *out = NULL;
    return 0;
  }

  Elf_Data *ulp_data = elf_getdata(ulp_scn, NULL);
  assert(ulp_data->d_buf != NULL && ulp_data->d_size > 0);

  /* In case a prefix is given, copy it to the path buffer.  */
  uint32_t path_size = 0;
  if (prefix) {
    strncpy(path_buffer, prefix, PATH_MAX);
    path_size += strlen(prefix);

    if (path_size >= PATH_MAX) {
      WARN("metadata path is too large: has %u bytes, expected %d.", path_size,
           PATH_MAX);
      return 0;
    }
  }

  /* Get full path to patch buffer.  */
  if (realpath(livepatch, &path_buffer[path_size]) == NULL) {
    WARN("Unable to retrieve realpath to %s", livepatch);
    return 0;
  }
  path_size = strlen(path_buffer) + 1;

  if (path_size >= PATH_MAX) {
    WARN("metadata path is too large: has %u bytes, expected %d.", path_size,
         PATH_MAX);
    return 0;
  }

  /* Create buffer large enough to hold the final metadata.  */
  uint32_t meta_size = ulp_data->d_size + path_size + sizeof(uint32_t);
  if (meta_size >= ULP_METADATA_BUF_LEN) {
    WARN("metadata content is too large: has %u bytes, expected less than %u.",
         meta_size, ULP_METADATA_BUF_LEN);
    return 0;
  }
  char *final_meta = (char *)malloc(meta_size);
  char *meta_head = final_meta;

  /* Copy the final metadata into final_meta buffer.  Things works here as
   * follows:
   *
   * 1. Copy the first 1 + 32 bytes containing the patch type and patch id.
   * 2. Copy the size of the path to the livepatch container file.
   * 3. Copy the path to the livepatch container file.
   * 4. Copy the remaining metadata stuff.
   *
   * We do it in this way so we don't have to carry the path to the patch
   * container with the patch. This info can be retrieved from the path to
   * patch and avoid problems regarding the application running in another path
   * than the ulp tool.
   * */
  memcpy(meta_head, ulp_data->d_buf, 1 + 32);
  meta_head += 1 + 32;
  memcpy(meta_head, &path_size, sizeof(uint32_t));
  meta_head += sizeof(uint32_t);
  memcpy(meta_head, path_buffer, path_size);
  meta_head += path_size;
  memcpy(meta_head, ulp_data->d_buf + 1 + 32, ulp_data->d_size - (1 + 32));

  unload_elf(&elf, &fd);

  *out = final_meta;
  return meta_size;
}

/** @brief Extract .ulp section from livepatch container .so
 *
 * Extract the content of the .ulp section within the livepatch container .so
 * file into a temporary file, and returns the path to it.
 *
 * This function also injects the path to the livepatch container (.so) into
 * the extracted metadata file.
 *
 * Returns a path to temporary file. The string must be free'd.
 *
 * @param livepatch  Path to livepatch container (.so)
 * @param revert     Extract the revert patch instead.
 *
 * @return Path to temporary file containing the metadata.
 * */
char *
extract_ulp_from_so_to_disk(const char *livepatch, bool revert)
{
  FILE *file;
  char *buf;
  size_t meta_size;

  meta_size = extract_ulp_from_so_to_mem(livepatch, revert, &buf, NULL);

  if (meta_size == 0 || buf == NULL) {
    return NULL;
  }

  char *tmp_path = strdup(create_path_to_tmp_file());
  file = fopen(tmp_path, "wb");
  if (!file) {
    WARN("Unable to open temporary file %s: %s", tmp_path, strerror(errno));
    free(tmp_path);
    return NULL;
  }

  if (fwrite(buf, sizeof(uint8_t), meta_size, file) != meta_size) {
    remove(tmp_path);
    fclose(file);
    free(buf);
    WARN("Error writing to %s: %s", tmp_path, strerror(errno));
    free(tmp_path);
    return NULL;
  }

  free(buf);
  fflush(file);
  fclose(file);

  return tmp_path;
}

int
load_patch_info_from_mem(void *src, size_t size)
{
  return parse_metadata_from_mem(&ulp, src, size);
}

/* Takes LIVEPATCH as a path to a livepatch metadata file, opens it,
 * parses the data, and fills the global variable 'ulp'. On Success,
 * returns 0.
 */
int
load_patch_info_from_disk(const char *livepatch)
{
  uint32_t c;
  uint32_t i, j;
  struct ulp_object *obj;
  struct ulp_unit *unit, *prev_unit = NULL;
  struct ulp_dependency *dep, *prev_dep = NULL;
  FILE *file;

  DEBUG("reading live patch metadata from %s.", livepatch);

  file = fopen(livepatch, "rb");
  if (!file) {
    WARN("Unable to open metadata file: %s.", livepatch);
    return ENOENT;
  }

  /* read metadata header information */
  ulp.objs = NULL;

  if (fread(&ulp.type, sizeof(uint8_t), 1, file) < 1) {
    WARN("Unable to read patch type.");
    return EINVALIDULP;
  }

  if (fread(&ulp.patch_id, sizeof(char), 32, file) < 32) {
    WARN("Unable to read patch id.");
    return EINVALIDULP;
  }

  if (fread(&c, sizeof(uint32_t), 1, file) < 1) {
    WARN("Unable to read so filename length.");
    return EINVALIDULP;
  }

  ulp.so_filename = calloc(c + 1, sizeof(char));
  if (!ulp.so_filename) {
    WARN("Unable to allocate so filename buffer.");
    return EINVALIDULP;
  }

  if (fread(ulp.so_filename, sizeof(char), c, file) < c) {
    WARN("Unable to read so filename.");
    return EINVALIDULP;
  }

  obj = calloc(1, sizeof(struct ulp_object));
  if (!obj) {
    WARN("Unable to allocate memory for the patch objects.");
    return ENOMEM;
  }

  ulp.objs = obj;
  obj->units = NULL;

  if (fread(&c, sizeof(uint32_t), 1, file) < 1) {
    WARN("Unable to read build id length (trigger).");
    return EINVALIDULP;
  }
  obj->build_id_len = c;
  obj->build_id = calloc(c, sizeof(char));
  if (!obj->build_id) {
    WARN("Unable to allocate build id buffer.");
    return EINVALIDULP;
  }

  if (fread(obj->build_id, sizeof(char), c, file) < c) {
    WARN("Unable to read build id.");
    return EINVALIDULP;
  }

  obj->build_id_check = 0;

  if (fread(&c, sizeof(uint32_t), 1, file) < 1) {
    WARN("Unable to read object name length.");
    return EINVALIDULP;
  }

  /* shared object: fill data + read patching units */
  obj->name = calloc(c + 1, sizeof(char));
  if (!obj->name) {
    WARN("Unable to allocate object name buffer.");
    return EINVALIDULP;
  }

  if (fread(obj->name, sizeof(char), c, file) < c) {
    WARN("Unable to read object name.");
    return EINVALIDULP;
  }

  if (ulp.type == 2) {
    /*
     * Reverse patches do not have patching units nor dependencies,
     * so return right away.
     */
    return 0;
  }

  if (fread(&obj->nunits, sizeof(uint32_t), 1, file) < 1) {
    WARN("Unable to read number of patching units.");
    return 1;
  }

  /* read all patching units for object */
  for (j = 0; j < obj->nunits; j++) {
    unit = calloc(1, sizeof(struct ulp_unit));
    if (!unit) {
      WARN("Unable to allocate memory for the patch units.");
      return ENOMEM;
    }

    if (fread(&c, sizeof(uint32_t), 1, file) < 1) {
      WARN("Unable to read unit old function name length.");
      return EINVALIDULP;
    }

    unit->old_fname = calloc(c + 1, sizeof(char));
    if (!unit->old_fname) {
      WARN("Unable to allocate unit old function name buffer.");
      return EINVALIDULP;
    }

    if (fread(unit->old_fname, sizeof(char), c, file) < c) {
      WARN("Unable to read unit old function name.");
      return EINVALIDULP;
    }

    if (fread(&c, sizeof(uint32_t), 1, file) < 1) {
      WARN("Unable to read unit new function name length.");
      return EINVALIDULP;
    }

    unit->new_fname = calloc(c + 1, sizeof(char));
    if (!unit->new_fname) {
      WARN("Unable to allocate unit new function name buffer.");
      return EINVALIDULP;
    }

    if (fread(unit->new_fname, sizeof(char), c, file) < c) {
      WARN("Unable to read unit new function name.");
      return EINVALIDULP;
    }

    if (fread(&unit->old_faddr, sizeof(void *), 1, file) < 1) {
      WARN("Unable to read old function address.");
      return EINVALIDULP;
    }

    if (obj->units) {
      prev_unit->next = unit;
    }
    else {
      obj->units = unit;
    }
    prev_unit = unit;
  }

  /* read dependencies */
  if (fread(&c, sizeof(uint32_t), 1, file) < 1) {
    WARN("Unable to read number of dependencies.");
    return EINVALIDULP;
  }

  for (i = 0; i < c; i++) {
    dep = calloc(1, sizeof(struct ulp_dependency));
    if (!dep) {
      WARN("Unable to allocate memory for dependency state.");
      return ENOMEM;
    }
    if (fread(&dep->dep_id, sizeof(char), 32, file) < 32) {
      WARN("Unable to read dependency patch id.");
      return EINVALIDULP;
    }
    if (ulp.deps) {
      prev_dep->next = dep;
    }
    else {
      ulp.deps = dep;
    }
    prev_dep = dep;
  }

  fclose(file);
  return 0;
}

/*
 * Checks if the livepatch container .so file contains the functions
 * specified in the global 'ulp' units. Returns 0 if every function is
 * present in the container file, and 1 otherwise.
 *
 * Before calling this function, the global variable 'ulp' should have
 * been initialized, typically by calling load_patch_info().
 */
static int
check_livepatch_functions_matches_metadata(const char *prefix)
{
  const char *so_filename = ulp.so_filename;
  const struct ulp_unit *curr_unit;
  void *container_handle;

  int ret = 0;

  /* If a prefix has been passed to trigger then we should remove it from the
     path, as it is only intended to get libpulp.so to find the correct path
     to library.  It is assumed that ulp tool can always reach it.  */
  if (prefix) {
    int prefix_len = strlen(prefix);

    /* Check that the prefix is there in the string.  */
    assert(strncmp(prefix, so_filename, prefix_len) == 0);

    so_filename += prefix_len;
  }

  /* Open livepatch container .so file temporarly.  */
  container_handle = dlopen(so_filename, RTLD_LOCAL | RTLD_LAZY);

  if (!container_handle) {
    WARN("failed to load container livepatch file in %s: %s.", so_filename,
         dlerror());
    return EINVAL;
  }

  /* Iterate over all unit objects in the metadata file.  */
  for (curr_unit = ulp.objs->units; curr_unit != NULL;
       curr_unit = curr_unit->next) {
    const char *new_fname = curr_unit->new_fname;
    void *symbol;

    /* Check if symbol exists.  If not, return error.  */
    symbol = dlsym(container_handle, new_fname);

    if (!symbol) {
      WARN("symbol %s is not present in the livepatch container: %s",
           new_fname, dlerror());
      ret = EINVAL;
      break;
    }
  }

  dlclose(container_handle);
  return ret;
}

/*
 * Checks if the livepatch parsed into the global variable 'ulp' is
 * suitable to be applied to PROCESS. Returns 0 if it is. Otherwise,
 * prints warning messages and returns 1.
 *
 * Before calling this function, the global variable 'ulp' should have
 * been initialized, typically by calling load_patch_info().
 */
int
check_patch_sanity(struct ulp_process *process, const char *prefix)
{
  const char *target;
  struct ulp_dynobj *d;

  DEBUG("checking that the live patch is suitable for the target process.");

  if (ulp.objs == NULL || ulp.objs->name == NULL) {
    WARN("metadata has not been properly parsed.");
    return EUNKNOWN;
  }

  if (check_livepatch_functions_matches_metadata(prefix)) {
    WARN("metadata contain functions that are not present in the livepatch.");
    return EUNKNOWN;
  }

  target = get_basename(ulp.objs->name);
  const unsigned char *buildid = NULL;

  /* check if the affected library is present in the process. */
  for (d = dynobj_first(process); d != NULL; d = dynobj_next(process, d)) {
    bool buildid_match = false;
    bool name_match = false;
    const char *basename = get_basename(d->filename);

    if (strcmp(basename, target) == 0) {
      buildid = d->build_id;
      name_match = true;
    }

    if (memcmp(ulp.objs->build_id, d->build_id, BUILDID_LEN) == 0)
      buildid_match = true;

    if (name_match && buildid_match)
      break;
  }

  if (!d) {
    int ret;
    if (buildid) {
      /* strdup because buildid_to_string returns a pointer to a static
         variable.  */
      char *buildid_str = strdup(buildid_to_string(buildid));
      char *lp_buildid = strdup(buildid_to_string((void *)ulp.objs->build_id));

      DEBUG("pid = %d, name = %s: livepatch buildid mismatch for %s (%s)\n"
            "    expected buildid: %s\n",
            process->pid, get_process_name(process), target, buildid_str,
            lp_buildid);

      free(buildid_str);
      free(lp_buildid);
      ret = EBUILDID;
    }
    else {
      DEBUG("pid = %d, name = %s: target library (%s) not loaded.",
            process->pid, get_process_name(process), target);
      ret = ENOTARGETLIB;
    }
    DEBUG("available target libraries:");
    for (d = dynobj_first(process); d != NULL; d = dynobj_next(process, d))
      DEBUG("  %s (%s)", d->filename, buildid_to_string(d->build_id));
    return ret;
  }

  return 0;
}

#if defined ENABLE_STACK_CHECK && ENABLE_STACK_CHECK
/*
 * Opens /proc/PID/maps and searches for the addresses where LIBRARY have been
 * loaded into. Then updates RANGE_START and RANGE_END with the lowest and
 * highest addresses that contain the library. Returns 0 on success and 1 on
 * error.
 */
int
library_range_detect(pid_t pid, char *library, uintptr_t *range_start,
                     uintptr_t *range_end)
{
  FILE *fp;
  char *line;
  char *end;
  char *str;
  char procmaps[PATH_MAX];
  int retcode;
  size_t size;
  uintptr_t addr1;
  uintptr_t addr2;

  *range_start = UINTPTR_MAX;
  *range_end = 0;

  retcode = snprintf(procmaps, sizeof(procmaps), "/proc/%d/maps", pid);
  if (retcode < 0)
    return EINVAL;

  fp = fopen(procmaps, "r");
  if (fp == NULL)
    return ENOENT;

  size = PATH_MAX;
  line = malloc(size);

  errno = 0;
  while (getline(&line, &size, fp) > 0) {
    if (strstr(line, library) == NULL)
      continue;

    /* Parse the address range in the current line. */
    str = line;
    addr1 = strtoul(str, &end, 16);
    str = end + 1; /* Skip the dash used in the range output. */
    addr2 = strtoul(str, &end, 16);

    if (addr1 < *range_start)
      *range_start = addr1;
    if (addr2 > *range_end)
      *range_end = addr2;
  }
  if (errno)
    WARN("error parsing /proc/%d/maps: %s", pid, strerror(errno));

  free(line);
  fclose(fp);

  if (errno)
    return errno;
  return 0;
}

/*
 * Iterates over all threads in the target PROCESS, unwinds their stacks, and
 * checks whether any frame lies within the target LIBRARY. This provides a
 * coarse lock to live patching: if any thread is within the target library,
 * the trigger tool can avoid live patching altogether; on the other hand, if
 * no threads are within the target library, the live patch can be applied
 * without consistency concerns. Returns 0 if no frame in any of the threads
 * currently sits within the target library, 1 if any frame does, or -1 if some
 * error ocurred during the unwinding of the stacks.
 *
 * WARNING: this function is in the critical section, so it can only be
 * called after successful thread hijacking.
 */
int
coarse_library_range_check(struct ulp_process *process, char *library)
{
  int found;
  int retcode;
  uintptr_t range_start;
  uintptr_t range_end;

  void *context;
  unw_addr_space_t as;
  unw_cursor_t cursor;
  unw_word_t pc;

  struct ulp_thread *thread;

  /* Optionally retrieve library name from patch metadata. */
  if (library == NULL)
    library = ulp.objs->name;

  DEBUG("checking if process %d is within %s.", process->pid, library);

  /* Determine the in-memory address range of the target library. */
  retcode =
      library_range_detect(process->pid, library, &range_start, &range_end);
  if (retcode)
    return -1;

  DEBUG("library memory range is [0x%lx..0x%lx].", range_start, range_end);

  /* Check every thread in the process. */
  found = 0;
  for (thread = process->threads; thread; thread = thread->next) {
    DEBUG("thread id %d:", thread->tid);

    /* Initialize libunwind. */
    context = _UPT_create(thread->tid);
    if (context == NULL)
      return -1;
    as = unw_create_addr_space(&_UPT_accessors, 0);
    if (as == NULL)
      goto error_path_context;
    retcode = unw_init_remote(&cursor, as, context);
    if (retcode)
      goto error_path_address_space;

    /* Compare every program counter on the stack against the range. */
    while (1) {
      /* Read the program counter. */
      retcode = unw_get_reg(&cursor, UNW_REG_IP, &pc);
      if (retcode)
        goto error_path_address_space;

      DEBUG("  pc=0x%lx", pc);

      /* Range check. */
      if (range_start < pc && pc < range_end)
        found++;
      if (found)
        break;

      /* Unwind to the previous frame. */
      retcode = unw_step(&cursor);
      if (retcode == 0)
        break;
      if (retcode < 0)
        goto error_path_address_space;
    }

    /* Release libunwind resources. */
    unw_destroy_addr_space(as);
    _UPT_destroy(context);

    /* Stop the search if the current thread is within range. */
    if (found)
      break;
  }

  DEBUG("stack check complete, found %d frames within the library", found);

  return found;

/* Clean up and return with error. */
error_path_address_space:
  unw_destroy_addr_space(as);
error_path_context:
  _UPT_destroy(context);
  return -1;
}
#endif

/** @brief Read applied patch linked list object from remote process
 *
 * The applied patches are maintained in libpulp.so in the __ulp_state object.
 * Retrieve the patch list there from the remote process.
 *
 * @param addr Address to read, where ulp_applied_patch object is.
 * @param pid  Pid of remote process.
 *
 * @return A `ulp_applied_patch` linked list.
 */
static struct ulp_applied_patch *
read_ulp_applied_patch(Elf64_Addr addr, pid_t pid)
{
  struct ulp_applied_patch *a_state;

  if (addr == 0)
    return NULL;

  a_state = calloc(1, sizeof(*a_state));
  if (!a_state) {
    WARN("error allocating memory.");
    return NULL;
  }

  if (read_memory((char *)a_state, sizeof(*a_state), pid, addr)) {
    WARN("error reading patch state.");
    free(a_state);
    return NULL;
  }

  if (a_state->lib_name != NULL) {
    read_string((char **)&a_state->lib_name, pid,
                (Elf64_Addr)a_state->lib_name);
  }

  if (a_state->container_name != NULL) {
    read_string((char **)&a_state->container_name, pid,
                (Elf64_Addr)a_state->container_name);
  }

  /* ulp_applied_unit and ulp_applied_patch is not used, so don't read it. But
     set it to NULL to avoid dangling pointers.  */

  a_state->units = NULL;
  a_state->deps = NULL;

  a_state->next = read_ulp_applied_patch((Elf64_Addr)a_state->next, pid);

  return a_state;
}

/** @brief Release ulp_applied_patch object list
 *
 * @param p  The ulp_applied_patch linked list object.
 */
void
release_ulp_applied_patch(struct ulp_applied_patch *p)
{
  if (p == NULL)
    return;

  release_ulp_applied_patch(p->next);

  if (p->lib_name)
    free((void *)p->lib_name);
  if (p->container_name)
    free((void *)p->container_name);

  free(p);
}

/** @brief Read applied patch linked list object from remote process
 *
 * The applied patches are maintained in libpulp.so in the __ulp_state object.
 * Retrieve the patch list there from the remote process.
 *
 * @param process Process to read from.
 *
 * @return A `ulp_applied_patch` linked list.
 */
struct ulp_applied_patch *
ulp_read_state(struct ulp_process *process)
{
  struct ulp_patching_state state;
  pid_t pid = process->pid;

  struct ulp_applied_patch *ret;

  if (!process->dynobj_libpulp || !process->dynobj_libpulp->state) {
    WARN("patching state address is NULL.");
    return NULL;
  }

  if (attach(process->pid)) {
    DEBUG("Unable to attach to %d to read data.\n", process->pid);
    ret = NULL;
    goto detach_process;
  }

  if (read_memory((char *)&state, sizeof(state), pid,
                  (Elf64_Addr)process->dynobj_libpulp->state)) {
    WARN("Error reading patches state.");
    ret = NULL;
    goto detach_process;
  }

  ret = read_ulp_applied_patch((Elf64_Addr)state.patches, pid);

detach_process:
  if (detach(process->pid)) {
    DEBUG("Unable to detach %d.\n", process->pid);
    return ret;
  }

  return ret;
}

/** @brief Read error state of libpulp in remote process `p`.
 *
 * This function reads the error state of libpulp on the remote process `p`.
 *
 * @param p    Remote process to read from.
 *
 * @return     EINVAL, ENOLIBPULP, EOLDLIBPULP in case of error, or the error
 *             state of libpulp in the target process.
 */
ulp_error_t
get_libpulp_error_state(struct ulp_process *p)
{
  if (!p)
    return EINVAL;

  if (!p->dynobj_libpulp)
    return ENOLIBPULP;

  ulp_error_t state = EUNKNOWN;
  Elf64_Addr err_state_addr = p->dynobj_libpulp->error_state;

  if (err_state_addr) {
    int ret = read_memory(&state, sizeof(state), p->pid, err_state_addr);
    if (ret) {
      WARN("Error reading libpulp error state.");
      return EUNKNOWN;
    }

    return state;
  }

  /* Old libpulp perhaps?  */
  if (p->dynobj_libpulp->trigger) {
    return EOLDLIBPULP;
  }

  return EUNKNOWN;
}
