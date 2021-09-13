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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>

#include "arguments.h"
#include "check.h"
#include "config.h"
#include "introspection.h"
#include "ulp_common.h"

extern struct ulp_metadata ulp;

int
run_check(struct arguments *arguments)
{
  const char *livepatch;
  int ret;
  int check;
  int result;

  struct ulp_process target;

  /* Set the verbosity level in the common introspection infrastructure. */
  ulp_verbose = arguments->verbose;
  ulp_quiet = arguments->quiet;

  livepatch = arguments->args[0];

  if (load_patch_info(livepatch)) {
    WARN("error parsing the metadata file (%s).", livepatch);
    return 1;
  }

  memset(&target, 0, sizeof(target));
  target.pid = arguments->pid;
  ret = initialize_data_structures(&target);
  if (ret) {
    WARN("error gathering target process information.");
    return -1;
  }

  if (check_patch_sanity(&target)) {
    WARN("error checking live patch sanity.");
    return -1;
  }

  ret = hijack_threads(&target);
  if (ret == -1) {
    FATAL("fatal error during live patch application (hijacking).");
    return -1;
  }
  if (ret > 0) {
    WARN("unable to hijack process.");
    return -1;
  }

  check = patch_applied(&target, ulp.patch_id, &result);
  if (check == -1) {
    FATAL("fatal error during live patch status check (hijacked execution).");
  }
  else if (check) {
    WARN("error during live patch status check (hijacked execution).");
  }

  ret = restore_threads(&target);
  if (ret) {
    FATAL("fatal error during live patch application (restoring).");
    return -1;
  }

  /*
   * When patch_applied returns an error, signal the parent with -1.
   * Otherwise, forward the result of the check routine, i.e. 0 if the
   * patch has been previously applied, or 1 if it hasn't.
   */
  if (check)
    return -1;
  if (result == 0)
    WARN("patch not yet applied");
  else
    WARN("patch already applied");
  return result;
}
