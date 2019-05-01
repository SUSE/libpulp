#include <stdio.h>

int __attribute__((weak)) bar() {
    fprintf(stderr, "this is a weak function\n");
    return 0;
}
