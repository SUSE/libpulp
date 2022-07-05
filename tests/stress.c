#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define NUM_PROCESSES 4000

int value(void);

typedef enum
{
  NONE = 0,
  READY,
  LIVEPATCHED,
} state_t;

int
child_main(volatile state_t *state)
{
  *state = READY;

  while (value()) {
    sleep(1);
  }

  *state = LIVEPATCHED;
  return 0;
}

int
main(void)
{
  pid_t pids[NUM_PROCESSES];
  volatile state_t *states;
  states = mmap(NULL, NUM_PROCESSES * sizeof(state_t), PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  for (int i = 0; i < NUM_PROCESSES; i++) {
    states[i] = NONE;
    pids[i] = fork();

    if (pids[i] == 0) {
      /* Child.  */
      return child_main(&states[i]);
    }
  }

  for (int i = 0; i < NUM_PROCESSES; i++) {
    while (states[i] != READY)
      usleep(1000);
  }

  puts("Processes launched");

  for (int i = 0; i < NUM_PROCESSES; i++) {
    while (states[i] != LIVEPATCHED)
      usleep(1000);
  }

  for (int i = 0; i < NUM_PROCESSES; i++) {
    int wstatus;
    waitpid(pids[i], &wstatus, 0);

    if (WIFEXITED(wstatus)) {
      int r = WEXITSTATUS(wstatus);
      if (r) {
        printf("Process %d returned non-zero: %d\n", pids[i], r);
      }
    }
    else {
      printf("Process %d ended without calling exit\n", pids[i]);
    }
  }

  munmap((void *)states, NUM_PROCESSES * sizeof(state_t));
  puts("Processes finished");

  return 0;
}
