#include <stdio.h>
#include <unistd.h>
#include "../libdummy/libdummy.h"

int main() {
    fprintf(stderr, "ex3: Hello there :))\n");
    foo(1);
    fprintf(stderr, "THIS IS EX3: ");
    while (sleeping_bar(3)) {fprintf(stderr, "THIS IS EX3: ");}
    foo(2);
}
