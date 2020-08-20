/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2020 SUSE Linux GmbH
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

#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libparameters.h>

void
handler (int sig,
         siginfo_t *info __attribute__ ((unused)),
         void *ucontext __attribute__ ((unused)))
{
  if (sig == SIGHUP)
    printf("%d\n", parameters(1, 2, 3, 4));
}

int
main (void)
{
  struct sigaction act;

  memset(&act, 0, sizeof(act));
  act.sa_sigaction = handler;
  act.sa_flags = SA_SIGINFO;
  errno = 0;
  if (sigaction(SIGHUP, &act, NULL)) {
    perror("sigaction:");
    return errno;
  }

  printf("Waiting for signals.\n");
  while (1) {
    pause();
  }

  return 1;
}
