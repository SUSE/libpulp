#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* At least one thread is required to cause the deadlock, otherwise,
 * malloc/calloc refrain from acquiring a lock, at all.
 */
#define THREADS 1

/* A live-patchable library is required so that a live patch can be
 * applied, however, this test case only relies on the fact that
 * multiple threads in the application use malloc/calloc, not on
 * anything specific to libblocked (any live-patchable library could
 * have been used).
 */
#include <libblocked.h>

/* Do not optimize, otherwise the calloc/free sequences go away. */
#pragma GCC optimize ("O0")

void *
worker (void *arg __attribute__ ((unused)))
{
  while (1) {
    pause ();
  }
}

int
main (void)
{
  char *data;
  pthread_t thread[THREADS];

  for (int iter = 0; iter < THREADS; iter++)
    pthread_create (&thread[iter], NULL, worker, NULL);

  /* Simple call to the target library, not necessary to demonstrate the
   * deadlock per se, but required to make this application depend on
   * a live-patchable library.
   */
  hello ();

  /* Signal readiness. */
  printf ("Waiting for signals.\n");

  /* Use calloc on a tight loop, which increases the chance of hitting
   * the deadlock.
   */
  while (1) {
    data = calloc (100, sizeof(char));
    free (data);
  }

  return 0;
}
