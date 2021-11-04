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
#include <link.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
#include <unistd.h>

#include "arguments.h"
#include "config.h"
#include "introspection.h"
#include "trigger.h"
#include "ulp_common.h"

static int
trigger_one_process(int pid, int retries, const char *livepatch,
                    const char *revert_library)
{
  struct ulp_process *target = calloc(1, sizeof(struct ulp_process));
  int result;
  int ret;

  target->pid = pid;

  if (livepatch && load_patch_info(livepatch)) {
    WARN("error parsing the metadata file (%s).", livepatch);
    return 1;
  }

  ret = initialize_data_structures(target);
  if (ret) {
    WARN("error gathering target process information.");
    ret = 1;
    goto target_clean;
  }

  if (livepatch && check_patch_sanity(target)) {
    WARN("error checking live patch sanity.");
    ret = 1;
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
    if (ret == -1) {
      FATAL("fatal error during live patch application (hijacking).");
      ret = 1;
      goto target_clean;
    }
    if (ret > 0) {
      WARN("unable to hijack process.");
      ret = 1;
      goto target_clean;
    }

#if defined ENABLE_STACK_CHECK && ENABLE_STACK_CHECK
    if (arguments->check_stack) {
      ret = coarse_library_range_check(target, NULL);
      if (ret) {
        DEBUG("range check failed");
        goto range_check_failed;
      }
    }
#endif
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
    usleep(1000);
  }

  if (result) {
    WARN("live patching failed.");
    ret = 1;
    goto target_clean;
  }

  WARN("live patching succeeded.");
  ret = 0;

target_clean:
  release_ulp_process(target);
  return ret;
}

int
run_trigger(struct arguments *arguments)
{
  /* Set the verbosity level in the common introspection infrastructure. */
  ulp_verbose = arguments->verbose;
  ulp_quiet = arguments->quiet;

  const char *livepatch = arguments->args[0];
  const char *revert_library = arguments->library;
  int retry = arguments->retries;
  pid_t pid = arguments->pid;

  return trigger_one_process(pid, retry, livepatch, revert_library);
}
