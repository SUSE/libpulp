#include <pthread.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>

/* Pointer to the original sum variable.  This will be initialized with the
   address of `sum` when the patch is loaded in the program, as described in
   the .dsc file.  */
volatile long *sum_ptr = NULL;

/* Pointer to the original lock.  */
pthread_mutex_t *sum_lock_ptr = NULL;

void accumulate_2(long x __attribute__((unused)))
{
  assert(sum_ptr && sum_lock_ptr);

  if (pthread_mutex_lock(sum_lock_ptr) != 0) {
    abort();
  }

  *sum_ptr = 0;

  if (pthread_mutex_unlock(sum_lock_ptr) != 0) {
    abort();
  }
}
