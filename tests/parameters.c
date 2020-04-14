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
