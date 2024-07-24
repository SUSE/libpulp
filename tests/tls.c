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
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define NUM_THREADS 2

static pthread_t threads[NUM_THREADS];
static pthread_barrier_t barrier;

char *banner_get(void);
char **banner_get_ref(void);
void banner_set(char *);

/* On two threads this should work.  If more, race conditions will appear.  */
static volatile int gate1 = 0;
static volatile int gate2 = 0;

void *
thread_func(void *arg)
{
  long i = (long)arg;
  static __thread char buf[256];

  if (i == 1) {
    // Thread 1 must be slower and print after thread 0.
    while (gate1 == 0)
      usleep(1000); // Await.
  }

  /* Original banner. */
  printf("Banner addr: 0x%lX\n", (unsigned long)banner_get_ref());
  printf("%s\n", banner_get());

  sprintf(buf, "Banner changed from thread_func: %lu\n", i);

  /* Use original banner setting function. */
  banner_set(strdup(buf));
  printf("%s\n", banner_get());

  if (i == 0) {
    // Allow thread 1 to run.
    gate1++;
  }

  pthread_barrier_wait(&barrier);

  if (i == 1) {
    // Thread 1 must be slower and print after thread 0.
    while (gate2 == 0)
      usleep(1000); // Await.
  }

  /*
   * Use banner setting function again, which is supposed to have been
   * changed by the test driver. The patched function ignores the
   * argument, so 'String from main' should not be in the output.
   */

  sprintf(buf, "String from thread_func: %lu\n", i);
  banner_set(buf);
  printf("%s\n", banner_get());

  if (i == 0) {
    // Allow thread 1 to run.
    gate2++;
  }

  return NULL;
}

static void
create_threads()
{
  int i;
  for (i = 0; i < NUM_THREADS; i++) {
    if (pthread_create(&threads[i], NULL, thread_func, (void *)((long)i))) {
      errx(1, "Thread creation failure.");
    }
  }
}

static void
join_threads()
{
  int i;
  for (i = 0; i < NUM_THREADS; i++) {
    if (pthread_join(threads[i], NULL)) {
      errx(1, "Thread join failure.");
    }
  }
}

int
main(void)
{
  char buffer[128];
  pthread_barrier_init(&barrier, NULL, NUM_THREADS + 1);

  create_threads();

  /* Wait for input. */
  if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
    if (errno) {
      perror("tls");
      return 1;
    }
  }

  pthread_barrier_wait(&barrier);
  join_threads();

  return 0;
}
