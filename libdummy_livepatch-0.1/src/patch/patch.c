#include <stdio.h>

int new_bar() {
    fprintf(stderr, "LIVEPATCHED!\n");
    return 1;
}
