/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2023 SUSE Software Solutions GmbH
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

/* Program to set a seccomp filter blocking mprotect calls with EXEC flag.  */

#define _GNU_SOURCE

#include <unistd.h>
#include <seccomp.h>
#include <errno.h>
#include <stdio.h>

#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/un.h>

static int
block_mprotect(void)
{
  scmp_filter_ctx *seccomp;
  int r;

  seccomp = seccomp_init(SCMP_ACT_ALLOW);
  if (!seccomp)
    return -ENOMEM;

  r = seccomp_rule_add(
                  seccomp,
                  SCMP_ACT_ERRNO(EPERM),
                  SCMP_SYS(mmap),
                  1,
                  SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC|PROT_WRITE, PROT_EXEC|PROT_WRITE));
  if (r < 0)
    goto finish;

  r = seccomp_rule_add(
                  seccomp,
                  SCMP_ACT_ERRNO(EPERM),
                  SCMP_SYS(mprotect),
                  1,
                  SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, PROT_EXEC));
  if (r < 0)
    goto finish;

  r = seccomp_attr_set(seccomp, SCMP_FLTATR_CTL_NNP, 0);
  if (r < 0)
    goto finish;

  r = seccomp_load(seccomp);

finish:
  seccomp_release(seccomp);
  return r;
}

static int
launch_process(int argc, char *argv[])
{
  (void)argc;

  /* Launch target process.  */
  return execv(argv[0], (char *const *)argv);
}

static int
check_args(int argc, char *argv[])
{
  (void)argv;

  if (argc < 2) {
    /* No target process.  */
    printf("No target binary specified\n");
    return 1;
  }

  return 0;
}

int main(int argc, char *argv[])
{
  if (check_args(argc, argv)) {
    return 1;
  }

  int r = block_mprotect();
  if (r) {
    printf("mprotect protect failure: %s\n", strerror(-r));
    return 1;
  }

  return launch_process(--argc, ++argv);
}
