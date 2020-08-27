/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2020 SUSE Software Solutions GmbH
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
#include <malloc.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* At least one thread is required to cause the deadlock, otherwise,
 * malloc/calloc refrain from acquiring a lock, at all.
 */
#define THREADS 50

/* A live-patchable library is required so that a live patch can be
 * applied, however, this test case only relies on the fact that
 * multiple threads in the application use malloc/calloc, not on
 * anything specific to libblocked (any live-patchable library could
 * have been used).
 */
#include <libblocked.h>

/* Do not optimize, otherwise the calloc/free sequences go away. */
#pragma GCC push_options
#pragma GCC optimize ("O0")

/* Calls many of the functions that acquire the locks that might cause
 * live-patch installation to deadlock.
 */
void *
worker (void *arg __attribute__ ((unused)))
{
  void *handle;
  void *symbol __attribute__ ((unused));
  char *data;

  while (1) {
    data = calloc (100, sizeof(char));
    data = reallocarray (data, 200, sizeof(char));
    free (data);
    data = malloc (300 * sizeof(char));
    data = realloc (data, 400 * sizeof(char));
    free (data);
    data = aligned_alloc (256, 500 * sizeof(char));
    free (data);
    data = valloc (600 * sizeof(char));
    free (data);
    data = pvalloc (700 * sizeof(char));
    free (data);
    if (!posix_memalign ((void **) &data, 512, 800 * sizeof(char)))
      free (data);

    handle = dlopen (NULL, RTLD_LAZY | RTLD_NOLOAD);
    if (handle != NULL) {
      symbol = dlsym (handle, "worker");
      dlclose (handle);
    }

    /* Sleep for a brief while to increase the chances that the
     * application of the live-patch succeeds.
     */
    usleep (1);
  }
}

/* Restore optimization level. */
#pragma GCC pop_options

int
main (void)
{
  char buffer[128];
  pthread_t thread[THREADS];

  /* Create THREADS threads that try to allocate and free memory in an
   * infinite loop.
   */
  for (int iter = 0; iter < THREADS; iter++)
    pthread_create (&thread[iter], NULL, worker, NULL);

  /* Signal readiness. */
  printf ("Waiting for input.\n");

  /* Wait for any input, then call hello(), which should produce
   * different output before and after the live-patching.
   */
  while (1) {
    if (fgets (buffer, sizeof(buffer), stdin) == NULL) {
      if (errno) {
        perror ("deadlock");
        return 1;
      }
      printf ("Reached the end of file; quitting.\n");
      return 0;
    }
    hello ();
  }

  return 0;
}
