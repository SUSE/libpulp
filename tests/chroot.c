#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include "libparameters.h"

int
main(void)
{
  char buffer[128];

  if (chroot("/proc")) {
    /* Permission error, skip the test.  */
    printf("chroot error\n");
    return 77;
  }

  /* Loop waiting for any input. */
  printf("Waiting for input.\n");
  while (1) {
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
      if (errno) {
        perror("chroot");
        return 1;
      }
      printf("Reached the end of file; quitting.\n");
      return 0;
    }
    int_params(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
    float_params(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
  }

  return 1;
}
