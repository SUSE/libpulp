#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include "libdummy.h"

void *f1(void *arg __attribute__ ((unused))) {
    while (sleeping_bar(1)) {};
    return NULL;
}

void *f2(void *arg __attribute__ ((unused))) {
    eternal_sleeper_bar(1);
    return NULL;
}

int main() {
    pthread_t tid1, tid2;

    pthread_create(&tid1, NULL, f1, NULL);
    pthread_create(&tid2, NULL, f2, NULL);

    pthread_join(tid1, NULL);
    pthread_join(tid2, NULL);
}
