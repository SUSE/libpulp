#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

void
handler (int sig,
         siginfo_t *info __attribute__ ((unused)),
         void *ucontext __attribute__ ((unused)))
{
  char *data;

  /* Should not call calloc (AS-Unsafe) from a signal handler. */
  if (sig == SIGUSR1) {
    printf ("handler entry\n");
    fflush (stdout);
    data = calloc (100, sizeof(char));
    free (data);
    printf ("handler exit\n");
    fflush (stdout);
  }
}

void *
worker (void *arg __attribute__ ((unused)))
{
  char *data;

  while (1) {
    pause ();
  }
}

int
main (void)
{
  char *data;
  struct sigaction act;
  pthread_t thread[THREADS];
  sigset_t set;

  memset(&act, 0, sizeof(act));
  act.sa_sigaction = handler;
  act.sa_flags = SA_SIGINFO;
  errno = 0;
  if (sigaction(SIGUSR1, &act, NULL)) {
    perror("sigaction:");
    return 1;
  }

  sigemptyset (&set);
  sigaddset (&set, SIGUSR1);
  pthread_sigmask (SIG_BLOCK, &set, NULL);
  for (int iter = 0; iter < THREADS; iter++)
    pthread_create (&thread[iter], NULL, worker, NULL);
  pthread_sigmask (SIG_UNBLOCK, &set, NULL);

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
