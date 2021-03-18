/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2021 SUSE Software Solutions GmbH
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

#include <err.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <libblocked.h>

void *
function(void *arg __attribute__((unused)))
{
  /* Call a blocking library function (unblocks on interruptions). */
  hello_loop();

  return NULL;
}

int
main(void)
{
  int retcode;
  void *retval;
  pthread_t thread;

  retcode = pthread_create(&thread, NULL, function, NULL);
  if (retcode)
    errx(EXIT_FAILURE, "Unable to create thread.\n");

  sleep(1);

  retcode = pthread_cancel(thread);
  if (retcode)
    errx(EXIT_FAILURE, "Unable to send cancelation request.\n");

  retcode = pthread_join(thread, &retval);
  if (retcode)
    errx(EXIT_FAILURE, "Unable to join thread.\n");
  if (retval != PTHREAD_CANCELED)
    errx(EXIT_FAILURE, "Thread not canceled.\n");

  printf("OK.\n");

  return 0;
}
