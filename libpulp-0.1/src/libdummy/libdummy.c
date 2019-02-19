#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void foo(int n) {
    fprintf(stderr, "example: foo %d\n", n);
}

int bar() {
    fprintf(stderr, "example: locked behind bars...\n");
    foo(3);
    return 1;
}

int sleeping_bar(int time) {
    fprintf(stderr, "example: locked behind sleepin' bars...\n");
    sleep(time);
    fprintf(stderr, "example: sleepin' bars returning...\n");
    return 1;
}

int loop_bar(int time) {
    while(sleeping_bar(time)) { sleep(rand() % 5); }
    fprintf(stderr, "leaving loop_bar\n");
    return 1;
}
