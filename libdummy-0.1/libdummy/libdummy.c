#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/syscall.h>

void foo(int n) {
    fprintf(stderr, "[THREAD %lu] ", syscall(SYS_gettid));
    fprintf(stderr, "example: foo %d\n", n);
}

int bar() {
    fprintf(stderr, "[THREAD %lu] ", syscall(SYS_gettid));
    fprintf(stderr, "example: locked behind bars...\n");
    foo(3);
    return 1;
}

int sleeping_bar(int time) {
    fprintf(stderr, "[THREAD %lu] ", syscall(SYS_gettid));
    fprintf(stderr, "example: locked behind sleepin' bars...\n");
    sleep(time);
    return 1;
}

int loop_bar(int time) {
    while(sleeping_bar(time)) { sleep(rand() % 5); }
    fprintf(stderr, "[THREAD %lu] ", syscall(SYS_gettid));
    fprintf(stderr, "leaving loop_bar\n");
    return 1;
}

int eternal_sleeper_bar(int time) {
    while (1) {
    //   fprintf(stderr, "[THREAD %lu] ", syscall(SYS_gettid));
       sleeping_bar(time);
    }
    return 1;
}
