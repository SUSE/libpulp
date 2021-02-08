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

#include "config.h"
#include "introspection.h"

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
 * global and thread-local, per-library universe counters. Returns 0 on
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
  read_local_universes(process);

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

/* Prints all the info collected about the processes in PROCESS_LIST. */
void
print_process_list(struct ulp_process *process_list)
{
  struct ulp_process *process_item;
  struct ulp_dynobj *object_item;
  struct thread_state *state_item;

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

    printf("  Local universes:\n");
    object_item = process_item->dynobj_targets;
    if (!object_item)
      printf("    (none)\n");
    while (object_item) {
      printf("    in %s:\n", object_item->filename);
      state_item = object_item->thread_states;
      while (state_item) {
        printf("      thread #%06d: ", state_item->tid);
        if (state_item->universe == (unsigned long)-1)
          printf("OK (queued - not currently in the library)\n");
        else if (state_item->universe < process_item->global_universe)
          printf("NOK (blocked - thread-local universe=%lu)\n",
                 state_item->universe);
        else
          printf("OK (ready - thread-local universe=%lu)\n",
                 state_item->universe);
        state_item = state_item->next;
      }
      object_item = object_item->next;
    }
    process_item = process_item->next;
    printf("\n");
  }
}

const char *argp_program_version = PACKAGE_STRING;

struct arguments
{
  pid_t pid;
};

static error_t
parser(int key, char *arg, struct argp_state *state)
{
  struct arguments *arguments;

  arguments = state->input;

  switch (key) {
    case 'p':
      arguments->pid = atoi(arg);
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }

  return 0;
}

int
main(int argc, char **argv)
{
  static struct argp_option options[] = {
    { "pid", 'p', "PID", 0,
      "Only gather status from process with id == PID"
      "\t(when not provided, checks all processes)",
      0 },
    { 0 }
  };
  static struct argp argp = { options, parser, NULL, NULL, NULL, NULL, NULL };

  struct arguments arguments;
  struct ulp_process *process_list;

  arguments.pid = 0;
  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  /*
   * If the PID argument has not been provided, check all live patchable
   * processes; otherwise, just the request process.
   */
  if (arguments.pid == 0)
    process_list = build_process_list();
  else {
    process_list = NULL;
    insert_target_process(arguments.pid, &process_list);
  }

  print_process_list(process_list);

  return 0;
}
