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

#include "introspection.h"
#include "ulp_common.h"

struct ulp_process target;
extern struct ulp_metadata ulp;

int
check_args(int argc, char *argv[])
{
  if (argc != 3) {
    WARN("Usage: %s <pid> <livepatch metadata path>", argv[0]);
    return 1;
  }

  if (strlen(argv[2]) > ULP_PATH_LEN) {
    WARN("livepatch path is limited to %d bytes.", ULP_PATH_LEN);
    return 2;
  }

  return 0;
}

int
main(int argc, char **argv)
{
  int pid;
  char *livepatch;
  int patched = -1;
  int ret;

  if (check_args(argc, argv))
    return 2;
  pid = atoi(argv[1]);
  livepatch = argv[2];

  if (load_patch_info(livepatch)) {
    WARN("Unable to load patch info.");
    return 3;
  }

  target.pid = pid;
  ret = initialize_data_structures(&target);
  if (ret) {
    if (ret == EAGAIN)
      return EAGAIN;
    else
      return 4;
  }

  /* verify if to-be-patched libs support libpulp */
  if (check_patch_sanity(&target))
    return 5;

  if (hijack_threads(&target))
    return 6;

  if (patch_applied(&target, ulp.patch_id) == 1)
    patched = 1;
  else
    patched = 0;

  if (restore_threads(&target))
    return 9;

  return patched;
}
