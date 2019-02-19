#include <stdio.h>

int new_bar() {
    fprintf(stderr, "LIVEPATCHED!\n");
    return 1;
}

int new_sleeping_bar(int time) {
    fprintf(stderr, "SLEEPIN' LIVEPATCHED %d\n", time);
    sleep(time);
    return 1;
}
