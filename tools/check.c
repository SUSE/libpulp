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

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
#include <argp.h>

#include "arguments.h"
#include "check.h"
#include "config.h"
#include "error_common.h"
#include "introspection.h"
#include "ulp_common.h"

extern struct ulp_metadata ulp;

int
run_check(struct arguments *arguments)
{
  const char *container;
  char *livepatch;
  size_t livepatch_size;
  int ret;
  int check;
  int result;

  struct ulp_process *target = calloc(1, sizeof(struct ulp_process));

  /* Set the verbosity level in the common introspection infrastructure. */
  ulp_verbose = arguments->verbose;
  ulp_quiet = arguments->quiet;

  container = arguments->args[0];

  livepatch_size =
      extract_ulp_from_so_to_mem(container, false, &livepatch, NULL);

  if (!livepatch) {
    WARN("error extracting .ulp section from %s", container);
    ret = 1;
    goto ulp_process_clean;
  }

  if (load_patch_info_from_mem(livepatch, livepatch_size)) {
    WARN("error parsing the metadata file (%s).", livepatch);
    ret = 1;
    goto ulp_process_clean;
  }

  if (isnumber(arguments->process_wildcard)) {
    target->pid = atoi(arguments->process_wildcard);
  }
  else {
    WARN("check does not support process wildcard");
    ret = -1;
    goto ulp_process_clean;
  }

  ret = initialize_data_structures(target);
  if (ret) {
    WARN("error gathering target process information.");
    ret = -1;
    goto ulp_process_clean;
  }

  if (check_patch_sanity(target, NULL)) {
    WARN("error checking live patch sanity.");
    ret = -1;
    goto ulp_process_clean;
  }

  ret = hijack_threads(target);
  if (ret == ETHRDDETTACH) {
    FATAL("fatal error during live patch application (hijacking).");
    ret = -1;
    goto ulp_process_clean;
  }
  if (ret > 0) {
    WARN("unable to hijack process.");
    ret = -1;
    goto ulp_process_clean;
  }

  check = patch_applied(target, ulp.patch_id, &result);
  if (check == -1) {
    FATAL("fatal error during live patch status check (hijacked execution).");
  }
  else if (check) {
    WARN("error during live patch status check (hijacked execution).");
  }

  ret = restore_threads(target);
  if (ret) {
    FATAL("fatal error during live patch application (restoring).");
    ret = -1;
    goto ulp_process_clean;
  }

  /*
   * When patch_applied returns an error, signal the parent with -1.
   * Otherwise, forward the result of the check routine, i.e. 0 if the
   * patch has been previously applied, or 1 if it hasn't.
   */
  if (check) {
    ret = -1;
    goto ulp_process_clean;
  }
  if (result == 0)
    WARN("patch not yet applied");
  else
    WARN("patch already applied");
  ret = result;

ulp_process_clean:
  free(livepatch);
  release_ulp_process(target);
  return ret;
}

struct argp_option *
get_command_option_check(void)
{
  static struct argp_option options[] = {
    { 0, 0, 0, 0, "Options:", 0 },
    { "verbose", 'v', 0, 0, "Produce verbose output", 0 },
    { "quiet", 'q', 0, 0, "Don't produce any output", 0 },
    { "process", 'p', "process", 0, "Target process name, wildcard, or PID", 0 },
    { 0 }
  };

  return options;
}
