#include <iostream>
#include <unistd.h>
#include <pthread.h>

#define noinline __attribute__((noinline))
#define NUM_ACCUMULATORS 4

volatile long sum;
pthread_mutex_t sum_lock = PTHREAD_MUTEX_INITIALIZER;

/* Accumulate into a global variable.  */
// Will be livepatched;
void noinline accumulate(long x)
{
  if (pthread_mutex_lock(&sum_lock) != 0) {
    abort();
  }

  sum += x;

  if (pthread_mutex_unlock(&sum_lock) != 0) {
    abort();
  }
}

void *accumulator(void* x)
{
  for (long i = 0; i < 100000000L; i++) {
    accumulate(i);
  }

  return NULL;
}

int main(void)
{
  pthread_t threads[NUM_ACCUMULATORS];

  for (int i = 0; i < NUM_ACCUMULATORS; i++) {
    if (pthread_create(&threads[i], NULL, accumulator, NULL) != 0) {
      abort();
    }
  }

  for (int i = 0; i < NUM_ACCUMULATORS; i++) {
    if (pthread_join(threads[i], NULL) != 0) {
      abort();
    }
  }

  printf("sum = %ld\n", sum);

  return 0;
}
