#include <stdio.h>
#include <unistd.h>

#define NOINLINE __attribute__((noinline))

int NOINLINE
value()
{
  /* Avoid interprocedural const-propagation on clang.  */
  volatile int x = 0;
  return x;
}

int
main()
{
  puts("Ready.");

  while (value() == 0)
    usleep(100);

  puts("Livepatched");

  while (1)
    usleep(100);

  return 0;
}
