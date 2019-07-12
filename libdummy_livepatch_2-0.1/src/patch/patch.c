#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>

int new_bar() {
    fprintf(stderr, "[THREAD %lu] ", syscall(SYS_gettid));
    fprintf(stderr, "LIVEPATCHED TWICE!\n");
    return 1;
}

int new_sleeping_bar(int time) {
    fprintf(stderr, "[THREAD %lu] ", syscall(SYS_gettid));
    fprintf(stderr, "SLEEPIN' LIVEPATCHED TWICE (%d)\n", time);
    sleep(time);
    return 1;
}
