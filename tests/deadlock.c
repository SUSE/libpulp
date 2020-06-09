#include <dlfcn.h>
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
    fgets (buffer, 128, stdin);
    hello ();
  }

  return 0;
}
