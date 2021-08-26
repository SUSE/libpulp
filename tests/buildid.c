#include <stdio.h>

/* From libbuildid.c.  */
int retval(void);

int
main()
{
  while (1) {
    int ret;

    printf("Waiting for input.\n");
    getchar();

    ret = retval();
    printf("%d\n", ret);
  }

  return 0;
}
