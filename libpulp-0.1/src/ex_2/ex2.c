#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include "../libdummy/libdummy.h"

void *f1(void *arg) {
    fprintf(stderr, "ex2: Thread 1: entering bar from f1()\n");
    while (sleeping_bar(1)) { sleep(rand() % 3); }
    fprintf(stderr, "ex2: Thread 1: left bar from f1()\n");
}

void *f2(void *arg) {
    fprintf(stderr, "ex2: Thread 2: entering bar from f2()\n");
    loop_bar(20);
    fprintf(stderr, "ex2: Thread 2: left bar from f2()\n");
}

void *f3(void *arg) {
    fprintf(stderr, "ex2: Thread 3: entering bar from f3()\n");
    while (sleeping_bar(10)) { sleep(rand() % 3); }
    fprintf(stderr, "ex2: Thread 3: left bar from f3()\n");
}

int main() {
    pthread_t tid1, tid2, tid3;

    fprintf(stderr, "ex2: Hello from main thread :)\n");

    pthread_create(&tid1, NULL, f1, NULL);
    pthread_create(&tid2, NULL, f2, NULL);
    pthread_create(&tid3, NULL, f3, NULL);

    pthread_join(tid1, NULL);
    fprintf(stderr, "joined thread 1\n");
    pthread_join(tid2, NULL);
    fprintf(stderr, "joined thread 2\n");
    pthread_join(tid3, NULL);
    fprintf(stderr, "joined thread 3\n");
}
