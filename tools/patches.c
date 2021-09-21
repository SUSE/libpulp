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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "arguments.h"
#include "config.h"
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

/* Attaches to PROCESS multiple times and collect information about its
 * applied live patches and loaded libraries. Returns 0 on
 * success; 1 if process information was not properly parsed; and -1 if
 * process hijacking went wrong, which also means that PROCESS was
 * probably put into an inconsistent state and should be killed.
 */
int
get_process_universes(struct ulp_process *process)
{
  if (initialize_data_structures(process))
    return 1;

  if (hijack_threads(process))
    return -1;

  read_global_universe(process);

  if (restore_threads(process))
    return -1;

  return 0;
}

/* Inserts a new process structure into LIST if the process identified
 * by PID is live-patchable.
 */
void
insert_target_process(int pid, struct ulp_process **list)
{
  char mapname[PATH_MAX];
  FILE *map;

  struct ulp_process *new = NULL;

  snprintf(mapname, PATH_MAX, "/proc/%d/maps", pid);
  if ((map = fopen(mapname, "r")) == NULL) {
    /* EACESS error happens when the tool is executed by a regular user.
       This is not a hard error. */
    if (errno != EACCES)
      perror("Unable to open memory map for process");
    return;
  }

  /* If the process identified by PID is live patchable, add to LIST. */
  if (libpulp_loaded(map)) {
    new = malloc(sizeof(struct ulp_process));
    memset(new, 0, sizeof(struct ulp_process));

    new->pid = pid;
    if (get_process_universes(new)) {
      printf("Failed to parsed data for live-patchable process %d... "
             "Skipping.\n",
             pid);
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
build_process_list(void)
{
  long int pid;

  DIR *slashproc;
  struct dirent *subdir;

  struct ulp_process *list = NULL;

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
    /* Add live patchable process. */
    insert_target_process(pid, &list);
  }
  closedir(slashproc);

  return list;
}

/** @brief Convert build id provided in `build_id` into string.
 *
 * Example:
 *
 * with buildid: 338aa4d16c98dda7af170cc8e2b59d259bd5d4f4
 *
 * it will return the string:
 * "338aa4d16c98dda7af170cc8e2b59d259bd5d4f4"
 *
 * The string returned by this function is statically allocated and don't
 * require `free`.
 *
 * @param build_id The build id
 *
 * @return String representing buildid in hexadecimal format.
 */
const char *
buildid_to_string(const unsigned char build_id[BUILDID_LEN])
{
  static char build_id_str[2 * BUILDID_LEN + 1];
  int i;

  memset(build_id_str, '\0', sizeof(build_id_str));

  for (i = 0; i < BUILDID_LEN; i++)
    snprintf(&build_id_str[2 * i], 3, "%02x", (unsigned)build_id[i]);

  return build_id_str;
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
  struct ulp_dynobj *object_item;

  process_item = process_list;
  while (process_item) {

    printf("PID: %d\n", process_item->pid);

    printf("  Global universe: %ld\n", process_item->global_universe);

    printf("  Live patches:\n");
    object_item = process_item->dynobj_patches;
    if (!object_item)
      printf("    (none)\n");
    while (object_item) {
      printf("    %s\n", object_item->filename);
      object_item = object_item->next;
    }

    printf("  Loaded libraries:\n");
    object_item = process_item->dynobj_targets;
    if (!object_item)
      printf("    (none)\n");
    while (object_item) {
      if (print_buildid)
        printf("    in %s (%s):\n", object_item->filename,
               buildid_to_string(object_item->build_id));
      else
        printf("    in %s:\n", object_item->filename);

      object_item = object_item->next;
    }
    process_item = process_item->next;
    printf("\n");
  }
}

int
run_patches(struct arguments *arguments)
{
  struct ulp_process *process_list;
  int print_buildid = arguments->buildid;

  /*
   * If the PID argument has not been provided, check all live patchable
   * processes; otherwise, just the request process.
   */
  if (arguments->pid == 0)
    process_list = build_process_list();
  else {
    process_list = NULL;
    insert_target_process(arguments->pid, &process_list);
  }

  print_process_list(process_list, print_buildid);

  return 0;
}
