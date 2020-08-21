#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <dozens.h>
#include <hundreds.h>

int
main (void)
{
  char input[64];

  printf("Waiting for input.\n");
  while (1) {
    if (scanf("%s", input) == EOF) {
      if (errno) {
        perror("numserv");
        return 1;
      }
      printf("Reached the end of file; quitting.\n");
      return 0;
    }
    if (strncmp(input, "dozen", strlen("dozen")) == 0)
      printf("%d\n", dozen());
    if (strncmp(input, "hundred", strlen("hundred")) == 0)
      printf("%d\n", hundred());
    if (strncmp(input, "quit", strlen("quit")) == 0) {
      printf("Quitting.\n");
      return 0;
    }
  }

  return 1;
}
