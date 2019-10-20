#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

int fibo(int n);

int main(int argc, char *argv[])
{
    int r, i, j;
    clock_t t;
    double time;

    if (argc < 2) return -1;

    fprintf(stderr, "sleeping for: %d secs\n", atoi(argv[1]));
    sleep(atoi(argv[1]));

    for (i = 0; i < 46; i++) {
        for (j = 0; j < 10; j++) {
            t = clock();
            r = fibo(i);
            t = clock() - t;
            time = ((double) t) / CLOCKS_PER_SEC;
            fprintf(stderr, "fibo(%d), %d, %f\n", i, r, time);
         }
    }
    return 0;
}
