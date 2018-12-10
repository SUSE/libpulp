#include <stdio.h>
#include <unistd.h>

void foo(int n) {
    fprintf(stderr, "example: foo %d\n", n);
}

int bar() {
    fprintf(stderr, "example: locked behind bars...\n");
    foo(3);
    return 1;
}

int sleeping_bar() {
    fprintf(stderr, "example: locked behind bars...\n");
    sleep(2);
    return 1;
}


