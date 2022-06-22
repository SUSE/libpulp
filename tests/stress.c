#include <unistd.h>
#include <stdio.h>

int value(void);

int main(void)
{
  puts("Ready");

  while (value() != 0) {
    sleep(1);
  }

  return 0;
}
