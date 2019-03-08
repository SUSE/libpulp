#include <stdio.h>
#include <unistd.h>
#include "../libdummy/libdummy.h"

int main() {
    fprintf(stderr, "dummyapp: Hello there :))\n");
    foo(1);
    fprintf(stderr, "THIS IS EX1: ");
    while (bar()) { sleep(1); fprintf(stderr, "THIS IS EX1: ");}
    foo(2);
}
