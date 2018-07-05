#include <stdio.h>
#include "../libdummy/libdummy.h"

int main() {
    fprintf(stderr, "dummyapp: Hello there :))\n");
    foo(1);
    while (bar()) { sleep(1); }
    foo(2);
}
