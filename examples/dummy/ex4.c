#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include "libdummy.h"

void *f1(void *arg) {
    while (sleeping_bar(1)) {};
}

void *f2(void *arg) {
    eternal_sleeper_bar(1);
}

int main() {
    pthread_t tid1, tid2;

    pthread_create(&tid1, NULL, f1, NULL);
    pthread_create(&tid2, NULL, f2, NULL);

    pthread_join(tid1, NULL);
    pthread_join(tid2, NULL);
}
