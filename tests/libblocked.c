#include <stdio.h>
#include <unistd.h>

void
hello (void)
{
  printf ("hello\n");
}

/* Call hello to print on every interruption. */
void
hello_loop (void)
{
  while (1) {
    pause ();
    hello ();
  }
}
