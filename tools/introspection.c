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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <limits.h>
#include <link.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
#include <unistd.h>

#include "config.h"
#include "introspection.h"
#include "ulp_common.h"

#if defined ENABLE_STACK_CHECK && ENABLE_STACK_CHECK
#include <libunwind-ptrace.h>
#endif

struct ulp_metadata ulp;
int ulp_verbose;
int ulp_quiet;

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

static void
debug_ulp_object(struct ulp_object *obj)
{
  DEBUG("");
  DEBUG("obj: %lx", (unsigned long)obj);
  DEBUG("obj->build_id_len: %u", obj->build_id_len);
  DEBUG("obj->build_id_check: %u", obj->build_id_check);
  DEBUG("obj->build id: %lx", (unsigned long)obj->build_id);
  DEBUG("obj->name: %s", obj->name);
  DEBUG("obj->dl_handler: %lx", (unsigned long)obj->dl_handler);
  DEBUG("obj->flags: %lx", (unsigned long)obj->flag);
  DEBUG("obj->nunits: %u", obj->nunits);
  DEBUG("obj->units: %lx", (unsigned long)obj->units);
  DEBUG("");

  debug_ulp_unit(obj->units);
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

    if (obj->filename)
      free(obj->filename);
    if (obj->thread_states)
      free(obj->thread_states);
    free(obj);
  }
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
    free(p);
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
      WARN("error reading _DYNAMIC array.");
      return 1;
    }
    if (dyn.d_tag == DT_NULL) {
      WARN("error searching for r_debug.");
      return 1;
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
    WARN("error reading link_map address.");
    return 1;
  }

  if (read_memory((char *)&process->dynobj_main->link_map,
                  sizeof(struct link_map), process->pid, link_map)) {
    WARN("error reading link_map data.");
    return 1;
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

  /* If object has no link map attached to it, there is nothing we can do.  */
  if (!obj->link_map.l_addr) {
    DEBUG("no link map object found");
    return 1;
  }

  /* l_addr holds the pointer to the ELF header.  */
  ehdr_addr = obj->link_map.l_addr;

  /* Read ELF header from remote process.  */
  ret = read_memory((char *)&ehdr, sizeof(ehdr), pid, ehdr_addr);
  if (ret != 0) {
    WARN("Unable to read ELF header from process %d\n", pid);
    return 1;
  }

  /* Sanity check if process header size is valid.  */
  if (ehdr.e_phentsize != sizeof(ElfW(Phdr))) {
    WARN("Invalid phdr readed");
    return 1;
  }

  /* Get first process header address.  */
  phdr_addr = ehdr_addr + ehdr.e_phoff;

  /* Iterate over each process header.  */
  for (i = 0; i < ehdr.e_phnum; i++) {
    ElfW(Phdr) phdr;
    ElfW(Addr) curr_phdr_addr = phdr_addr + i * sizeof(ElfW(Phdr));

    /* Get first process header from remote process.  */
    ret = read_memory((char *)&phdr, sizeof(phdr), pid, curr_phdr_addr);
    if (ret != 0) {
      WARN("Unable to read process header from process %d\n", pid);
      return 0;
    }

    /* Look for the dynamic section.  */
    if (phdr.p_type == PT_DYNAMIC) {
      ElfW(Dyn) dyn;
      ElfW(Addr) dyn_addr = ehdr_addr + phdr.p_paddr;

      /* Iterate over each tag in this section.  */
      do {
        /* Get the dynamic symbol in remote process.  */
        ret = read_memory((char *)&dyn, sizeof(dyn), pid, dyn_addr);
        if (ret != 0) {
          WARN("Unable to read dynamic symbol from process %d\n", pid);
          return 0;
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
              WARN("DT_SYMENT value of %s is unexpected", obj->filename);
            break;

          case DT_HASH:
            hash_addr = dyn.d_un.d_ptr;
            if (!hash_addr)
              DEBUG("hash section found, but is empty");
            break;
        }
        dyn_addr += sizeof(dyn);
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
          WARN("Unable to read note header from process %d\n", pid);
          return 0;
        }

        name_len = note.n_namesz;
        buildid_len = note.n_descsz;

        /* Align with the 4 bytes boundary.  */
        buildid_len += buildid_len % 4;
        name_len += name_len % 4;

        if (note.n_type == NT_GNU_BUILD_ID) {
          /* Build id note section found.  */
          buildid_addr = note_addr + sizeof(note) + name_len;
          break;
        }

        note_addr += buildid_len + name_len + 12;
      }
      while (note_addr < note_addr_end);
    }
  }

  if (buildid_addr) {
    if (buildid_len == sizeof(obj->build_id)) {
      ret = read_memory((char *)obj->build_id, buildid_len, pid, buildid_addr);
      if (ret != 0) {
        WARN("Unable to read build id from target process %d", pid);
      }
    }
    else {
      WARN("build id length mismatch: expected %lu, got %d",
           sizeof(obj->build_id), buildid_len);
    }
  }
  else {
    WARN("build id length mismatch: expected %lu, got %d",
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
      WARN("Unable to read hash table");
      return 0;
    }
  }
  else {
    WARN("hash table not found in %s", obj->filename);
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
    WARN("error: unable to open auxv.");
    return 1;
  }

  do {
    if (read(auxv, &at, sizeof(Elf64_auxv_t)) != sizeof(Elf64_auxv_t)) {
      WARN("error: unable to read auxv.");
      return 1;
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
    WARN("error: unable to find entry address for the executable");
    return 1;
  }
  if (at_phdr == 0) {
    WARN("error: unable to find program header of target process");
    return 1;
  }
  if (phent != sizeof(phdr)) {
    WARN("error: invalid PHDR size for target process (32 bit process?)");
    return 1;
  }
  for (i = 0; i < phnum; i++) {
    if (read_memory((char *)&phdr, phent, process->pid, at_phdr + i * phent)) {
      WARN("error: unable to read PHDR entry");
      return 1;
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

  DEBUG("getting in-memory information about the main executable.");

  /* calloc initializes all to zero */
  obj = calloc(sizeof(struct ulp_dynobj), 1);
  if (!obj) {
    WARN("unable to allocate memory.");
    return 1;
  }

  obj->filename = malloc(PATH_MAX);
  snprintf(obj->filename, PATH_MAX, "/proc/%d/exe", process->pid);

  obj->next = NULL;

  process->dynobj_main = obj;

  if (dig_load_bias(process)) {
    WARN("unable to calculate the load bias for the executable.");
    return 1;
  }
  if (dig_main_link_map(process)) {
    WARN("unable to parse the mappings of objects in memory.");
    return 1;
  }

  return 0;
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
    aux_link_map = parse_lib_dynobj(process, obj_link_map);
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
    WARN("libpulp not loaded, thus live patching not possible.");
    return 1;
  }

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
struct link_map *
parse_lib_dynobj(struct ulp_process *process, struct link_map *link_map_addr)
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

  DEBUG("reading in-memory information about %s.", libname);

  obj->filename = libname;

  /* ensure that PIE was verified */
  if (!process->dynobj_main)
    return NULL;

  /*
   * While parsing a DSO, see if it exports the symbols required by
   * live-patching. Most symbols will be provided by libpulp.so, and
   * some by the target library.
   */

  /* Pointers to linux-vdso.so are invalid, so skip this library.  */
  if (strcmp(obj->filename, "linux-vdso.so.1"))
    parse_dynobj_elf_headers(pid, obj);

  /* Only libpulp.so should have those symbols exported.  */
  if (strstr(libname, "libpulp.so")) {
    DEBUG("Potential libpulp found");

    obj->trigger = get_loaded_symbol_addr(obj, pid, "__ulp_trigger");
    obj->path_buffer = get_loaded_symbol_addr(obj, pid, "__ulp_path_buffer");
    obj->check = get_loaded_symbol_addr(obj, pid, "__ulp_check_patched");
    obj->state = get_loaded_symbol_addr(obj, pid, "__ulp_state");
    obj->global =
        get_loaded_symbol_addr(obj, pid, "__ulp_get_global_universe");
    obj->msg_queue = get_loaded_symbol_addr(obj, pid, "__ulp_msg_queue");
    obj->revert_all = get_loaded_symbol_addr(obj, pid, "__ulp_revert_all");

    /* libpulp must expose all these symbols. */
    if (obj->trigger && obj->path_buffer && obj->check && obj->state &&
        obj->global && obj->revert_all) {
      obj->next = NULL;
      process->dynobj_libpulp = obj;
      DEBUG("(libpulp found)");
    }
    /* No other library should expose these symbols. */
    else if (obj->trigger || obj->path_buffer || obj->check || obj->state ||
             obj->global || obj->revert_all)
      WARN("unexpected subset of libpulp symbols exposed by %s.", libname);
  }

  /* Live patch objects. */
  /* XXX: Searching for the '_livepatch' substring in the filename of
   * a dynamically loaded object is rather frail. Alternatives:
   *   A. Have live patch DSOs expose some predefined symbol.
   *   B. Have libpulp mmap a .ulp or .rev file into memory.
   */
  if (strstr(obj->filename, "_livepatch")) {
    obj->next = process->dynobj_patches;
    process->dynobj_patches = obj;
  }
  /* All other libraries go into the targets list. */
  else {
    obj->next = process->dynobj_targets;
    process->dynobj_targets = obj;
  }

  return &obj->link_map;
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
  if (!process)
    return 1;

  DEBUG("getting in-memory information about process %d.", process->pid);

  if (parse_main_dynobj(process)) {
    WARN("unable to get in-memory information about the main executable.");
    return 1;
  }
  if (parse_libs_dynobj(process)) {
    WARN("unable to get in-memory information about shared libraries.");
    return 1;
  }

  /* Check if libpulp constructor has already been executed.  */
  struct ulp_patching_state ulp_state;
  if (read_memory((char *)&ulp_state, sizeof(ulp_state), process->pid,
                  process->dynobj_libpulp->state) ||
      ulp_state.load_state == 0) {
    WARN("libpulp not ready (constructors not yet run). Try again later.");
    return EAGAIN;
  }

  return 0;
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
  int i;

  DEBUG("advertising live patch ID to libpulp.");

  if (!process->all_threads_hijacked) {
    WARN("not all threads hijacked.");
    return 1;
  }

  thread = process->main_thread;
  path_addr = process->dynobj_libpulp->path_buffer;

  for (i = 0; i < 32; i++) {
    if (write_byte(patch_id[i], thread->tid, path_addr + i)) {
      WARN("Unable to write id byte %d.", i);
      return 1;
    }
  }

  return 0;
}

/*
 * Writes PATH into libpulp's '__ulp_path_buffer'. This operation is a
 * pre-condition to apply a new live patch. On success, returns 0.
 */
int
set_path_buffer(struct ulp_process *process, const char *path)
{
  struct ulp_thread *thread;
  Elf64_Addr path_addr;

  DEBUG("advertising live patch location to libpulp.");

  if (!process->all_threads_hijacked) {
    WARN("not all threads hijacked.");
    return 1;
  }

  thread = process->main_thread;
  path_addr = process->dynobj_libpulp->path_buffer;

  if (write_string(path, thread->tid, path_addr, ULP_PATH_LEN))
    return 1;

  return 0;
}

/*
 * Attaches to all threads in PROCESS, which causes them to stop. After
 * that, other introspection routines, such as set_id_buffer() and
 * set_path_buffer(), can be used. On success, returns 0. If anything
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
    return 1;
  }

  DEBUG("entering the critical section (process hijacking).");

  /* Open /proc/<pid>/task. */
  pid = process->pid;
  snprintf(taskname, PATH_MAX, "/proc/%d/task", pid);
  taskdir = opendir(taskname);
  if (taskdir == NULL) {
    WARN("error opening %s: %s.", taskname, strerror(errno));
    return 1;
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
    return -1;
  return 1;
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
    return 1;
  }

  if (set_id_buffer(process, id)) {
    WARN("unable to write live patch ID into target process memory.");
    return 1;
  }

  thread = process->main_thread;
  context = thread->context;
  routine = process->dynobj_libpulp->check;

  DEBUG(">>> running libpulp functions within target process...");
  ret = run_and_redirect(thread->tid, &context, routine);
  if (ret == -1) {
    WARN("fatal error during live patch status check.");
  };
  if (ret) {
    WARN("error during live patch status check.");
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
apply_patch(struct ulp_process *process, const char *metadata)
{
  int ret;
  struct ulp_thread *thread;
  struct user_regs_struct context;
  ElfW(Addr) routine;

  char full_path[PATH_MAX];
  unsigned full_path_size;

  DEBUG("beginning live patch application.");

  if (!process->all_threads_hijacked) {
    WARN("not all threads hijacked.");
    return 1;
  }

  /* The target program can be running in other directory where CWD is,
     therefore it is a good idea to pass the full path to the metadata
     info to avoid potential problems.  */
  if (!realpath(metadata, full_path)) {
    WARN("unable to retrieve full path to %s", metadata);
    return 1;
  }

  full_path_size = strlen(full_path) + 1; /* Include '\0'.  */
  if (full_path_size >= ULP_PATH_LEN) {
    WARN("full path to metadata file is too large");
    return 1;
  }

  if (set_path_buffer(process, full_path)) {
    WARN("unable to write live patch path into target process memory.");
    return 1;
  }

  thread = process->main_thread;
  context = thread->context;
  routine = process->dynobj_libpulp->trigger;

  DEBUG(">>> running libpulp functions within target process...");
  ret = run_and_redirect(thread->tid, &context, routine);
  if (ret == -1) {
    WARN("fatal error during live patch application.");
  };
  if (ret) {
    WARN("error during live patch application.");
  }
  DEBUG(">>> done.");
  if (ret)
    return ret;

  if (context.rax == EAGAIN)
    DEBUG("libc/libdl locks were busy: patch not applied.");

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

  if (!process->all_threads_hijacked) {
    WARN("not all threads hijacked.");
    return 1;
  }

  if (set_path_buffer(process, lib_name)) {
    WARN("unable to write library name into target process memory.");
    return 1;
  }

  thread = process->main_thread;
  context = thread->context;
  routine = process->dynobj_libpulp->revert_all;

  DEBUG(">>> running libpulp functions within target process...");
  ret = run_and_redirect(thread->tid, &context, routine);
  if (ret == -1) {
    WARN("fatal error during live patch revert.");
  };
  if (ret) {
    WARN("error during live patch revert.");
  }
  DEBUG(">>> done.");
  if (ret)
    return ret;

  if (context.rax == EAGAIN)
    DEBUG("libc/libdl locks were busy: patches not reversed.");

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
    return 1;
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

/* Takes LIVEPATCH as a path to a livepatch metadata file, opens it,
 * parses the data, and fills the global variable 'ulp'. On Success,
 * returns 0.
 */
int
load_patch_info(const char *livepatch)
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
    return 1;
  }

  /* read metadata header information */
  ulp.objs = NULL;

  if (fread(&ulp.type, sizeof(uint8_t), 1, file) < 1) {
    WARN("Unable to read patch type.");
    return 1;
  }

  if (fread(&ulp.patch_id, sizeof(char), 32, file) < 32) {
    WARN("Unable to read patch id.");
    return 2;
  }

  if (fread(&c, sizeof(uint32_t), 1, file) < 1) {
    WARN("Unable to read so filename length.");
    return 1;
  }

  ulp.so_filename = calloc(c + 1, sizeof(char));
  if (!ulp.so_filename) {
    WARN("Unable to allocate so filename buffer.");
    return 1;
  }

  if (fread(ulp.so_filename, sizeof(char), c, file) < c) {
    WARN("Unable to read so filename.");
    return 1;
  }

  obj = calloc(1, sizeof(struct ulp_object));
  if (!obj) {
    WARN("Unable to allocate memory for the patch objects.");
    return 1;
  }

  ulp.objs = obj;
  obj->units = NULL;

  if (fread(&c, sizeof(uint32_t), 1, file) < 1) {
    WARN("Unable to read build id length (trigger).");
    return 1;
  }
  obj->build_id_len = c;
  obj->build_id = calloc(c, sizeof(char));
  if (!obj->build_id) {
    WARN("Unable to allocate build id buffer.");
    return 1;
  }

  if (fread(obj->build_id, sizeof(char), c, file) < c) {
    WARN("Unable to read build id.");
    return 1;
  }

  obj->build_id_check = 0;

  if (fread(&c, sizeof(uint32_t), 1, file) < 1) {
    WARN("Unable to read object name length.");
    return 1;
  }

  /* shared object: fill data + read patching units */
  obj->name = calloc(c + 1, sizeof(char));
  if (!obj->name) {
    WARN("Unable to allocate object name buffer.");
    return 1;
  }

  if (fread(obj->name, sizeof(char), c, file) < c) {
    WARN("Unable to read object name.");
    return 1;
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
      return 1;
    }

    if (fread(&c, sizeof(uint32_t), 1, file) < 1) {
      WARN("Unable to read unit old function name length.");
      return 1;
    }

    unit->old_fname = calloc(c + 1, sizeof(char));
    if (!unit->old_fname) {
      WARN("Unable to allocate unit old function name buffer.");
      return 1;
    }

    if (fread(unit->old_fname, sizeof(char), c, file) < c) {
      WARN("Unable to read unit old function name.");
      return 1;
    }

    if (fread(&c, sizeof(uint32_t), 1, file) < 1) {
      WARN("Unable to read unit new function name length.");
      return 1;
    }

    unit->new_fname = calloc(c + 1, sizeof(char));
    if (!unit->new_fname) {
      WARN("Unable to allocate unit new function name buffer.");
      return 1;
    }

    if (fread(unit->new_fname, sizeof(char), c, file) < c) {
      WARN("Unable to read unit new function name.");
      return 1;
    }
    DEBUG(">> Just read new_fname: %s", unit->new_fname);

    if (fread(&unit->old_faddr, sizeof(void *), 1, file) < 1) {
      WARN("Unable to read old function address.");
      return 1;
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
    return 1;
  }

  for (i = 0; i < c; i++) {
    dep = calloc(1, sizeof(struct ulp_dependency));
    if (!dep) {
      WARN("Unable to allocate memory for dependency state.");
      return 1;
    }
    if (fread(&dep->dep_id, sizeof(char), 32, file) < 32) {
      WARN("Unable to read dependency patch id.");
      return 1;
    }
    if (ulp.deps) {
      prev_dep->next = dep;
    }
    else {
      ulp.deps = dep;
    }
    prev_dep = dep;
  }

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
check_livepatch_functions_matches_metadata(void)
{
  const char *so_filename = ulp.so_filename;
  const struct ulp_unit *curr_unit;
  void *container_handle;

  int ret = 0;

  /* Open livepatch container .so file temporarly.  */
  container_handle = dlopen(so_filename, RTLD_LOCAL | RTLD_LAZY);

  if (!container_handle) {
    WARN("failed to load container livepatch file in %s.", so_filename);
    return 1;
  }

  debug_ulp_object(ulp.objs);

  /* Iterate over all unit objects in the metadata file.  */
  for (curr_unit = ulp.objs->units; curr_unit != NULL;
       curr_unit = curr_unit->next) {
    const char *new_fname = curr_unit->new_fname;
    void *symbol;

    /* Check if symbol exists.  If not, return error.  */
    symbol = dlsym(container_handle, new_fname);

    if (!symbol) {
      WARN("symbol %s is not present in the livepatch container.", new_fname);
      ret = 1;
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
check_patch_sanity(struct ulp_process *process)
{
  char *target;
  struct ulp_dynobj *d;

  DEBUG("checking that the live patch is suitable for the target process.");

  if (ulp.objs == NULL || ulp.objs->name == NULL) {
    WARN("metadata has not been properly parsed.");
    return 1;
  }

  if (check_livepatch_functions_matches_metadata()) {
    WARN("metadata contain functions that are not present in the livepatch.");
    return 1;
  }

  target = strrchr(ulp.objs->name, '/');
  if (target) {
    /* strrchr returns pointer to the last occurence of '/'.  Therefore, the
       library base name should be one character ahead.  */
    target++;
  }
  else {
    /* name is already the library's basename.  */
    target = ulp.objs->name;
  }

  /* check if the affected library is present in the process. */
  for (d = process->dynobj_targets; d != NULL; d = d->next) {
    bool buildid_match = false;
    bool name_match = false;
    const char *basename = strrchr(d->filename, '/');

    if (basename)
      basename++;
    else
      basename = d->filename;

    if (strcmp(basename, target) == 0)
      name_match = true;

    if (memcmp(ulp.objs->build_id, d->build_id, BUILDID_LEN) == 0)
      buildid_match = true;

    if (name_match && buildid_match)
      break;
  }
  if (!d) {
    WARN("target library (%s) not loaded.", target);
    DEBUG("available target libraries:");
    for (d = process->dynobj_targets; d != NULL; d = d->next)
      DEBUG("  %s", d->filename);
    return 1;
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
    return 1;

  fp = fopen(procmaps, "r");
  if (fp == NULL)
    return 1;

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

  if (errno)
    return 1;
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
