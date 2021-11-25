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

#include <argp.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <libgen.h>
#include <link.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <unistd.h>

#include "arguments.h"
#include "config.h"
#include "introspection.h"
#include "patches.h"
#include "trigger.h"
#include "ulp_common.h"
#include "error_common.h"

/** Holds global variables used in this file. */
static struct
{
  int trigger_successes;
  int trigger_processes;
} globals;

#define TRIGGER_ERR_NONE 0
#define TRIGGER_ERR_UNKNOWN 1
#define TRIGGER_ERR_WRONG_PROCESS 2

/** @brief Apply a single live patch to one process.
 *
 *  This function does the dirty work of trigger: reverse and livepatching a
 *  process. It does so by checking if the given livepatch is suitable for
 *  the target process, and if so, proceeds hijacking all threads there
 *  to revert/apply patches.
 *
 *  @param pid       The pid of the process.
 *  @param retries   The number of retries to livepatch before giving up.
 *  @param livepatch The path to the metadata file (.ulp). Not necessary on
 *                   --revert-all unless atomic reverse & patch is desired.
 *  @param revert_library The library's basename which all livepatches will
 *                        be reversed.
 *
 *  @return 0 on success, anything else on error.
 */
static int
trigger_one_process(int pid, int retries, const char *livepatch,
                    const char *revert_library, bool check_stack)
{
  struct ulp_process *target = calloc(1, sizeof(struct ulp_process));
  int result;
  int ret;

  target->pid = pid;

  if (livepatch && load_patch_info(livepatch)) {
    WARN("error parsing the metadata file (%s).", livepatch);
    ret = TRIGGER_ERR_UNKNOWN;
    goto metadata_clean;
  }

  ret = initialize_data_structures(target);
  if (ret) {
    WARN("error gathering target process information.");
    ret = TRIGGER_ERR_UNKNOWN;
    goto target_clean;
  }

  if (livepatch && check_patch_sanity(target)) {
    /* Sanity may fail because the patch should not be applied to this
       process.  */
    ret = TRIGGER_ERR_WRONG_PROCESS;
    goto target_clean;
  }

  /*
   * Since live patching uses AS-Unsafe functions from the context of a
   * signal-handler, libpulp first checks whether the operation could
   * lead to a deadlock and returns with EAGAIN if so. Detaching and
   * briefly waiting usually changes the situation and the assessment,
   * so retry in a finite loop.
   */
  result = -1;
  int retry = retries;
  while (retry) {
    retry--;

    ret = hijack_threads(target);
    if (ret == ETHRDDETTACH) {
      FATAL("fatal error during live patch application (hijacking).");
      ret = TRIGGER_ERR_UNKNOWN;
      goto target_clean;
    }
    if (ret > 0) {
      WARN("unable to hijack process.");
      ret = TRIGGER_ERR_UNKNOWN;
      goto target_clean;
    }

    if (check_stack) {
#if defined ENABLE_STACK_CHECK && ENABLE_STACK_CHECK
      ret = coarse_library_range_check(target, NULL);
      if (ret) {
        DEBUG("range check failed");
        goto range_check_failed;
      }
#endif
    }
    if (revert_library) {
      result = revert_patches_from_lib(target, revert_library);
      if (result == -1) {
        FATAL("fatal error reverting livepatches (hijacked execution).");
        retry = 0;
      }
      if (result)
        DEBUG("live patching revert %d failed (attempt #%d).", target->pid,
              (retries - retry));
      else
        retry = 0;
    }

    if (livepatch) {
      result = apply_patch(target, livepatch);
      if (result == -1) {
        FATAL(
            "fatal error during live patch application (hijacked execution).");
        retry = 0;
      }
      if (result)
        DEBUG("live patching %d failed (attempt #%d).", target->pid,
              (retries - retry));
      else
        retry = 0;
    }
#if defined ENABLE_STACK_CHECK && ENABLE_STACK_CHECK
  range_check_failed:
#endif

    ret = restore_threads(target);
    if (ret) {
      FATAL("fatal error during live patch application (restoring).");
      retry = 0;
    }
    if (result)
      usleep(1000);
  }

  if (result) {
    WARN("live patching failed.");
    ret = TRIGGER_ERR_UNKNOWN;
    goto target_clean;
  }

  WARN("live patching succeeded.");
  ret = TRIGGER_ERR_NONE;

target_clean:
  release_ulp_process(target);
metadata_clean:
  release_ulp_global_metadata();
  return ret;
}

/** @brief Apply multiple live patches to one process.
 *
 *  This function reads all metadata files in `ulp_folder_path` and applies
 *  them to a process with pid = `pid`.
 *
 *  @param pid             The pid of the process.
 *  @param retries         The number of retries to livepatch before giving up.
 *  @param ulp_folder_path The path to the folder containing all metadata
 * files.
 *  @param revert_library  The library's basename which all livepatches will
 *                         be reversed.
 *
 *  @return 0 on success, anything else on error.
 */
static int
trigger_many_ulps(int pid, int retries, const char *wildcard_path,
                  const char *library, bool check_stack)
{
  const char *wildcard = get_basename(wildcard_path);
  char *ulp_folder_path = dirname(strdup(wildcard_path));
  DIR *directory = opendir(ulp_folder_path);
  struct dirent *entry;
  char buffer[ULP_PATH_LEN];

  if (!directory) {
    FATAL("Unable to open directory: %s", ulp_folder_path);
    free(ulp_folder_path);
    return 1;
  }

  while ((entry = readdir(directory)) != NULL) {
    struct stat stbuf;
    int bytes;
    memset(buffer, '\0', ULP_PATH_LEN);

    bytes = snprintf(buffer, ULP_PATH_LEN, "%s/%s", ulp_folder_path,
                     entry->d_name);
    if (bytes == ULP_PATH_LEN) {
      WARN("Path to %s is larger than %d bytes. Skipping...\n", entry->d_name,
           ULP_PATH_LEN);
      continue;
    }

    if (stat(buffer, &stbuf)) {
      WARN("Error retrieving stats for %s. Skiping...\n", buffer);
      continue;
    }

    if ((stbuf.st_mode & S_IFMT) == S_IFDIR) {
      /* Skip directories.  */
      continue;
    }

    const char *extension = strrchr(entry->d_name, '.');
    if (!extension) {
      /* File with no extension, skip.  */
      continue;
    }

    if (strcmp(extension, ".ulp")) {
      /* This is not an ULP file, skip.  */
      continue;
    }

    if (fnmatch(wildcard, entry->d_name, FNM_NOESCAPE) != 0) {
      /* Skip if file does not match wildcard.  */
      continue;
    }

    if (trigger_one_process(pid, retries, buffer, library, check_stack) == 0)
      globals.trigger_successes++;
    globals.trigger_processes++;
  }

  closedir(directory);

  free(ulp_folder_path);
  return 0;
}

/** @brief Apply multiple live patches to all processes with libpulp loaded.
 *
 *  This function reads all metadata files in `ulp_folder_path` and applies
 *  them to every process that haves libpulp loaded.
 *
 *  @param retries         The number of retries to livepatch before giving up.
 *  @param ulp_folder_path The path to the folder containing all metadata
 * files.
 *  @param revert_library  The library's basename which all livepatches will
 *                         be reversed.
 *
 *  @return 0 on success, anything else on error.
 */
static int
trigger_many_processes(int retries, const char *ulp_folder_path,
                       const char *library, bool check_stack)
{
  struct ulp_process *list = build_process_list();
  struct ulp_process *curr_item;
  int ret = 0;

  globals.trigger_successes = 0;
  globals.trigger_processes = 0;

  /* Iterate over the process list that have libpulp preloaded.  */
  for (curr_item = list; curr_item != NULL; curr_item = curr_item->next) {
    int r = trigger_many_ulps(curr_item->pid, retries, ulp_folder_path,
                              library, check_stack);

    /* If the livepatch failed because the patch wasn't targeted to the
       proccess, we ignore because we are batch processing.  */
    if (r != TRIGGER_ERR_WRONG_PROCESS)
      ret |= r;
  }

  if (!ulp_quiet)
    WARN("Succesfully applied %d patches\n", globals.trigger_successes);

  release_ulp_process(list);
  return ret;
}

/** @brief Trigger command entry point.
 */
int
run_trigger(struct arguments *arguments)
{
  /* Set the verbosity level in the common introspection infrastructure. */
  ulp_verbose = arguments->verbose;
  ulp_quiet = arguments->quiet;

  bool check_stack = false;
  const char *livepatch = arguments->args[0];
  const char *library = arguments->library;
  const char *ulp_folder_path = arguments->args[0];
  int retry = arguments->retries;
  pid_t pid = arguments->pid;
  int ret;

#if defined ENABLE_STACK_CHECK && ENABLE_STACK_CHECK
  check_stack = arguments->check_stack;
#endif

  if (pid > 0)
    ret = trigger_one_process(pid, retry, livepatch, library, check_stack);
  else {
    ret = trigger_many_processes(retry, ulp_folder_path, library, check_stack);
  }

  return ret;
}
