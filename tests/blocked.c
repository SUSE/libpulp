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
#include <pthread.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <libblocked.h>

void
handler (int sig __attribute__ ((unused)),
         siginfo_t *info __attribute__ ((unused)),
         void *ucontext __attribute__ ((unused)))
{
}

void *
function1(void *arg __attribute__ ((unused)))
{
  /* Signal readiness. */
  printf ("Waiting for signals.\n");

  /* Call a returning library function on every interruption. */
  while (1) {
    pause ();
    hello ();
  }
}

void *
function2(void *arg __attribute__ ((unused)))
{
  /* Signal readiness. */
  printf ("Waiting for signals.\n");

  /* Call a blocking library function (unblocks on interruptions). */
  while (1) {
    hello_loop ();
  }
}

int
main (void)
{
  struct sigaction act;

  pthread_t thread1;
  pthread_t thread2;
  sigset_t set;

  /* Register empty handlers for SIGUSR1 and SIGUSR2. */
  memset(&act, 0, sizeof(act));
  act.sa_sigaction = handler;
  act.sa_flags = SA_SIGINFO;
  errno = 0;
  if (sigaction(SIGUSR1, &act, NULL)) {
    perror("sigaction:");
    return 1;
  }
  if (sigaction(SIGUSR2, &act, NULL)) {
    perror("sigaction:");
    return 1;
  }

  /* The main thread ignores both SIGUSR1 and SIGUSR2. */
  sigemptyset (&set);
  sigaddset (&set, SIGUSR1);
  sigaddset (&set, SIGUSR2);
  pthread_sigmask (SIG_BLOCK, &set, NULL);

  /* thread1 accepts SIGUSR1, but not SIGUSR2. */
  sigemptyset (&set);
  sigaddset (&set, SIGUSR1);
  pthread_sigmask (SIG_UNBLOCK, &set, NULL);
  pthread_create (&thread1, NULL, function1, NULL);
  pthread_sigmask (SIG_BLOCK, &set, NULL);

  /* thread2 does the opposite. */
  sigemptyset (&set);
  sigaddset (&set, SIGUSR2);
  pthread_sigmask (SIG_UNBLOCK, &set, NULL);
  pthread_create (&thread2, NULL, function2, NULL);
  pthread_sigmask (SIG_BLOCK, &set, NULL);

  /* Wait for signals other than SIGUSR1 and SIGUSR2. */
  while (1)
    pause ();

  return 0;
}
