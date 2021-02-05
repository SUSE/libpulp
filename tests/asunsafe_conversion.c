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

#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>

#include <libblocked.h>

void
handler (int sig __attribute__ ((unused)),
         siginfo_t *info __attribute__ ((unused)),
         void *ucontext __attribute__ ((unused)))
{
  hello ();
}

int
main (void)
{
  void *handle;
  struct sigaction act;

  /* Register handler for SIGUSR1. */
  memset(&act, 0, sizeof(act));
  act.sa_sigaction = handler;
  act.sa_flags = SA_SIGINFO;
  errno = 0;
  if (sigaction(SIGUSR1, &act, NULL)) {
    perror("sigaction:");
    return 1;
  }

  /* Signal readiness. */
  printf ("Waiting for signals.\n");

  /* Wait for signals. */
  while (1) {
    /* Call dlopen functions in loop to make their locks busy. */
    handle = dlopen (NULL, RTLD_LAZY | RTLD_NOLOAD);
    if (handle != NULL) {
      dlclose (handle);
    }
  }

  return 0;
}
