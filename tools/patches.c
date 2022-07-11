/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2020-2021 SUSE Software Solutions GmbH
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

#include <argp.h>
#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <unistd.h>

#include "arguments.h"
#include "config.h"
#include "error_common.h"
#include "introspection.h"
#include "patches.h"

/* Returns 0 if libpulp.so has been loaded by the process with memory map
 * (/proc/<pid>/maps) opened in MAP. Otherwise, returns 1.
 */
int
libpulp_loaded(FILE *map)
{
  int retcode = 0;

  char *line = NULL;
  size_t len = 0;

  /* Read all lines of MAP and look for the 'libpulp.so' substring. */
  rewind(map);
  while (getline(&line, &len, map) != -1) {
    if (strstr(line, "libpulp.so")) {
      retcode = 1;
      break;
    }
  }

  /* Free structures allocated by getline() and return. */
  free(line);
  return retcode;
}

/** @brief Print all livepatches applied to library.
 *
 * @param patch   Patch object.
 * @param libname Base name of library.
 */
void
print_lib_patches(struct ulp_applied_patch *patch, const char *libname)
{
  /* Ensure that the basename was passed.  */
  libname = get_basename(libname);

  while (patch) {
    if (!strcmp(libname, patch->lib_name)) {
      printf("      livepatch: %s\n", patch->container_name);
    }
    patch = patch->next;
  }
}

/** @brief Check if function at `sym_address` has the NOP preamble.
 *
 * Functions that are livepatchable has ULP_NOPS_LEN - PRE_NOPS_LEN at the
 * beginning of the function. Check the existence of this preamble.
 *
 * @param sym_address  Address of function in target process.
 * @param pid          Pid of the target process.
 *
 * @return  True if preamble exists, false if not.
 */
static bool
check_preamble(ElfW(Addr) sym_address, pid_t pid)
{
  unsigned char bytes[2];

  if (read_memory((char *)bytes, 2, pid, sym_address)) {
    WARN("Unable to read symbol preable.");
    return false;
  }

  /* Check for NOP NOP or XGCH AX, AX.  */
  if ((bytes[0] == 0x90 || bytes[0] == 0x66) && bytes[1] == 0x90)
    return true;
  return false;
}

/** @brief Check if `libname` has a livepatch loaded.
 *
 * Check if the library with name `libname` has a livepatch loaded in the
 * `patch` chain.
 *
 * @param patch   List of loaded patches in the target process.
 * @param libname Name of the library in target process.
 *
 * @return true if libname has a livepatch loaded. False elsewhere.
 *
 */
static bool
has_livepatch_loaded(struct ulp_applied_patch *patch, const char *libname)
{
  if (libname == NULL)
    return false;

  /* Ensure that the basename was passed.  */
  libname = get_basename(libname);

  while (patch) {
    if (!strcmp(libname, patch->lib_name)) {
      return true;
    }
    patch = patch->next;
  }

  return false;
}

/** @brief Check if library in `obj` on target process is livepatchable.
 *
 * Check on the target process with `pid` if the library on `obj` is
 * livepatchable. The `patch` object with the target process loaded
 * livepatches is necessary because the following:
 *
 * A library is livepatchable if their functions has the ULP NOP preamble.
 * However, if the preamble does not exists, then:
 * 1. The library was already livepatched, and thus is livepatchable.
 * 2. The library is not livepatchable.
 *
 * @param patch  The list of patches loaded in the target process.
 * @param obj    The libary object.
 * @param pid    Pid of target process.
 *
 * @return       True if livepatchable, False if not.
 */
static bool
is_library_livepatchable(struct ulp_applied_patch *patch,
                         struct ulp_dynobj *obj, pid_t pid)
{
  int i, ret;
  if (has_livepatch_loaded(patch, obj->filename))
    return true;

  if (attach(pid)) {
    DEBUG("Unable to attach to %d to read data.\n", pid);
    ret = false;
    goto detach_process;
  }

  ElfW(Addr) ehdr_addr = obj->link_map.l_addr;

  ElfW(Addr) dynsym_addr = obj->dynsym_addr;

  /* Only look the first 64 symbols, else we may take too much time.  */
  int len = MIN(obj->num_symbols, 64);

  for (i = 0; i < len; i++) {
    ElfW(Sym) sym;

    ret = read_memory((char *)&sym, sizeof(sym), pid, dynsym_addr);
    if (ret) {
      WARN("Unable to read dynamic symbol");
      ret = false;
      goto detach_process;
    }

    ElfW(Addr) sym_addr = ehdr_addr + sym.st_value;

    if (check_preamble(sym_addr, pid)) {
      ret = true;
      goto detach_process;
    }

    dynsym_addr += sizeof(sym);
  }

detach_process:
  if (detach(pid)) {
    DEBUG("Unable to detach %d.\n", pid);
    return false;
  }

  return (bool)ret;
}

void
print_process(struct ulp_process *process, int print_buildid)
{
  struct ulp_dynobj *object_item;
  pid_t pid = process->pid;
  struct ulp_applied_patch *patch = ulp_read_state(process);
  printf("PID: %d, name: %s\n", pid, get_process_name(process));

  printf("  Livepatchable libraries:\n");
  object_item = dynobj_first(process);
  if (!object_item)
    printf("    (none)\n");
  while (object_item) {
    if (is_library_livepatchable(patch, object_item, pid)) {
      printf("    in %s", object_item->filename);
      if (print_buildid)
        printf(" (%s)", buildid_to_string(object_item->build_id));
      printf(":\n");

      print_lib_patches(patch, object_item->filename);
    }

    object_item = dynobj_next(process, object_item);
  }
  release_ulp_applied_patch(patch);
  printf("\n");
}

/** Do not create list and print process.  */
static bool print_process_instead = false;
static bool print_build_id = false;

/* Inserts a new process structure into LIST if the process identified
 * by PID is live-patchable.
 */
void
insert_target_process(int pid, struct ulp_process **list)
{
  char mapname[PATH_MAX];
  FILE *map;
  int ret;

  struct ulp_process *new = NULL;

  snprintf(mapname, PATH_MAX, "/proc/%d/maps", pid);
  if ((map = fopen(mapname, "r")) == NULL) {
    /* EACESS error happens when the tool is executed by a regular user.
       This is not a hard error.
       ENOENT happens when the process finished in between this process.  */
    if (errno != EACCES && errno != ENOENT)
      perror("Unable to open memory map for process");
    return;
  }

  /* If the process identified by PID is live patchable, add to LIST. */
  if (libpulp_loaded(map)) {
    new = malloc(sizeof(struct ulp_process));
    memset(new, 0, sizeof(struct ulp_process));

    new->pid = pid;
    ret = initialize_data_structures(new);
    if (ret) {
      WARN("Failed to parse data for live-patchable process %d: %s", pid,
           libpulp_strerror(ret));
    }
    if (print_process_instead) {
      print_process(new, print_build_id);
      release_ulp_process(new);
    }
    else {
      new->next = *list;
      *list = new;
    }
  }

  fclose(map);
}

/* Iterates over /proc and builds a list of live-patchable processes.
 * Returns said list.
 */
struct ulp_process *
build_process_list(const char *wildcard)
{
  long int pid;

  DIR *slashproc;
  struct dirent *subdir;

  struct ulp_process *list = NULL;

  if (isnumber(wildcard)) {
    /* If wildcard is actually a number, then treat it as a PID.  */
    pid = atoi(wildcard);
    insert_target_process(pid, &list);
    return list;
  }

  /* Build a list of all processes that have libpulp.so loaded. */
  slashproc = opendir("/proc");
  if (slashproc == NULL) {
    perror("Is /proc mounted?");
    return NULL;
  }

  while ((subdir = readdir(slashproc))) {
    /* Skip non-numeric directories in /proc. */
    if ((pid = strtol(subdir->d_name, NULL, 10)) == 0)
      continue;

    /* Optimization: If no wildcard is provided, do not bother geting target
       name because it doesn't matter.  */
    if (wildcard) {
      const char *process_name = get_target_binary_name(pid);
      /* Skip processes that does not match the wildcard. */
      if (wildcard != NULL && process_name != NULL &&
          fnmatch(wildcard, process_name, 0) != 0)
        continue;
    }

    /* If process is the ULP tool itself, skip it.  We cannot livepatch the
       tool itself.  Gödel and Cantor would not be proud...  */
    if (pid == getpid())
      continue;

    /* Add live patchable process. */
    insert_target_process(pid, &list);
  }
  closedir(slashproc);

  return list;
}

/** @brief Prints all the info collected about the processes in `process_list`.
 *
 * @param process_list List of processes.
 * @param print_buildid Print build id identifier of library.
 */
void
print_process_list(struct ulp_process *process_list, int print_buildid)
{
  struct ulp_process *process_item;

  process_item = process_list;
  while (process_item) {
    print_process(process_item, print_buildid);
    process_item = process_item->next;
  }
}

int
run_patches(struct arguments *arguments)
{
  print_build_id = arguments->buildid;
  ulp_quiet = arguments->quiet;
  ulp_verbose = arguments->verbose;
  print_process_instead = true;

  /*
   * If the PID argument has not been provided, check all live patchable
   * processes; otherwise, just the request process.
   */
  build_process_list(arguments->process_wildcard);

  return 0;
}
