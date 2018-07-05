#include <stdio.h>
#include "../libdummy/libdummy.h"

int main() {
    fprintf(stderr, "ex3: Hello there :))\n");
    foo(1);
    while (sleeping_bar()) {}
    foo(2);
}
