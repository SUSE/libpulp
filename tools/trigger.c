/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017-2020 SUSE Software Solutions GmbH
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

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <link.h>
#include <dirent.h>
#include <bfd.h>
#include <stddef.h>
#include <fcntl.h>
#include <sys/user.h>
#include <unistd.h>

#include "ulp_common.h"
#include "introspection.h"

struct ulp_process target;

int check_args(int argc, char *argv[])
{
    if (argc != 3)
    {
	WARN("Usage: %s <pid> <livepatch metadata path>", argv[0]);
	return 1;
    }

    if (strlen(argv[2]) > ULP_PATH_LEN)
    {
	WARN("livepatch path is limited to %d bytes.", ULP_PATH_LEN);
	return 2;
    }

    return 0;
}

int main(int argc, char **argv)
{
    int pid;
    char *livepatch;
    int ret;
    int retry;

    if (check_args(argc, argv)) return 2;
    pid = atoi(argv[1]);
    livepatch = argv[2];

    if (load_patch_info(livepatch))
    {
	WARN("Unable to load patch info.");
	return 3;
    }

    target.pid = pid;
    ret = initialize_data_structures(&target);
    if (ret) {
      if (ret == EAGAIN) return EAGAIN;
      else return 4;
    }

    /* verify if to-be-patched libs support libpulp */
    if (check_patch_sanity(&target))
      return 5;

    /* For RETRY Times, test if it would be safe to apply a live-patch,
     * i.e. if glibc internal locks for calloc and dlopen are free,
     * before actually applying it.
     */
    retry = 100;
    while (retry) {
      retry--;

      if (hijack_threads(&target)) return 6;

      /* Because apply_patch uses AS-Unsafe functions from the context
       * of a signal-handler, first check, with testlocks, that doing so
       * wouldn't cause a deadlock. If safe, call apply_patch,
       * otherwise, loop around and try again after a short while.
      */
      ret = testlocks(&target);
      if (ret) {
        WARN("Locks are busy, try again later (%d).", ret);
      }
      else {
        if (apply_patch(&target, livepatch))
          WARN("Apply patch to %d failed.", pid);
        else {
          WARN("Patching %d succesful.", pid);
          retry = 0;
        }
      }

      if (restore_threads(&target)) return 9;
      usleep (1000);
    }

    if (ret)
      return 1;
    return 0;
}
