#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "introspection.h"

/* Returns 0 if libulp.so has been loaded by the process with memory map
 * (/proc/<pid>/maps) opened in MAP. Otherwise, returns 1.
 */
int
libulp_loaded (FILE *map)
{
  int retcode = 0;

  char *line = NULL;
  size_t len = 0;

  /* Read all lines of MAP and look for the 'libulp.so' substring. */
  rewind (map);
  while (getline (&line, &len, map) != -1) {
    if (strstr (line, "libulp.so")) {
      retcode = 1;
      break;
    }
  }

  /* Free structures allocated by getline() and return. */
  free (line);
  return retcode;
}

/* Attaches to PROCESS multiple times and collect information about its
 * global and thread-local, per-library universe counters. Returns 0 on
 * success; 1 if process information was not properly parsed; and -1 if
 * process hijacking went wrong, which also means that PROCESS was
 * probably put into an inconsistent state and should be killed.
 */
int
get_process_universes (struct ulp_process *process)
{
  if (initialize_data_structures (process))
    return 1;

  if (hijack_threads (process))
    return -1;

  read_global_universe (process);
  read_local_universes (process);

  if (restore_threads (process))
    return -1;

  return 0;
}

/* Inserts a new process structure into LIST if the process identified
 * by PID is live-patchable.
 */
void
insert_target_process (int pid, struct ulp_process **list)
{
  char mapname[PATH_MAX];
  FILE *map;

  struct ulp_process *new = NULL;

  snprintf (mapname, PATH_MAX, "/proc/%d/maps", pid);
  if ((map = fopen (mapname, "r")) == NULL) {
    /* EACESS error happens when the tool is executed by a regular user.
       This is not a hard error. */
    if (errno != EACCES)
      perror ("Unable to open memory map for process");
    return;
  }

  /* If the process identified by PID is live patchable, add to LIST. */
  if (libulp_loaded (map)) {
    new = malloc (sizeof (struct ulp_process));
    memset (new, 0, sizeof (struct ulp_process));

    new->pid = pid;
    if (get_process_universes (new)) {
      printf ("Failed to parsed data for live-patchable proccess %d... "
              "Skipping.\n", pid);
    }
    else {
      new->next = *list;
      *list = new;
    }
  }

  fclose (map);
}

/* Iterates over /proc and builds a list of live-patchable processes.
 * Returns said list.
 */
struct ulp_process *
build_process_list (void)
{
  long int pid;

  DIR *slashproc;
  struct dirent *subdir;

  struct ulp_process *list = NULL;

  /* Build a list of all processes that have libulp.so loaded. */
  slashproc = opendir ("/proc");
  if (slashproc == NULL) {
    perror ("Is /proc mounted?");
    return NULL;
  }

  while ((subdir = readdir(slashproc))) {
    /* Skip non-numeric directories in /proc. */
    if ((pid = strtol (subdir->d_name, NULL, 10)) == 0)
      continue;
    /* Add live patchable process. */
    insert_target_process (pid, &list);
  }
  closedir (slashproc);

  return list;
}

/* Prints all the info collected about the processes in PROCESS_LIST. */
void
print_process_list (struct ulp_process *process_list)
{
  struct ulp_process *process_item;
  struct ulp_dynobj *object_item;
  struct thread_state *state_item;

  process_item = process_list;
  while (process_item) {

    printf ("PID: %d\n", process_item->pid);

    printf ("  Global universe: %ld\n", process_item->global_universe);

    printf ("  Live patches:\n");
    object_item = process_item->dynobj_patches;
    if (!object_item)
      printf ("    (none)\n");
    while (object_item) {
      printf ("    %s\n", object_item->filename);
      object_item = object_item->next;
    }

    printf ("  Local universes:\n");
    object_item = process_item->dynobj_targets;
    if (!object_item)
      printf ("    (none)\n");
    while (object_item) {
      printf ("    in %s:\n", object_item->filename);
      state_item = object_item->thread_states;
      while (state_item) {
        printf ("      thread #%06d: ", state_item->tid);
        if (state_item->universe == (unsigned long) -1)
          printf ("OK (queued - not currently in the library)\n");
        else if (state_item->universe < process_item->global_universe)
          printf ("NOK (blocked - thread-local universe=%lu)\n",
                  state_item->universe);
        else
          printf ("OK (ready - thread-local universe=%lu)\n",
                  state_item->universe);
        state_item = state_item->next;
      }
      object_item = object_item->next;
    }
    process_item = process_item->next;
    printf ("\n");
  }
}

int
main(void)
{
  struct ulp_process *process_list;

  process_list = build_process_list ();
  print_process_list (process_list);

  return 0;
}
