/* Include the C file so we have access to the implementation of the pcqueue
   without having to implement it into a library.  */

#include "../tools/pcqueue.c"

/* How many enqueues/dequeue.  */
#define NUM_TEST 1000000

static void *
producer_thread(void *a)
{
  long i;
  producer_consumer_t *pcqueue = a;

  for (i = 0; i < NUM_TEST; i++) {
    if (producer_consumer_enqueue(pcqueue, (void *)i) != 0) {
      abort();
    }
  }

  return NULL;
}

int
main()
{
  pthread_t thread;
  long i;

  producer_consumer_t *pcqueue = producer_consumer_new(8);
  if (pcqueue == NULL) {
    printf("Error allocating queue\n");
    return 1;
  }

  pthread_create(&thread, NULL, producer_thread, pcqueue);

  for (i = 0; i < NUM_TEST; i++) {
    void *elem = producer_consumer_dequeue(pcqueue);
    if ((long)elem != i)
      abort();
  }

  pthread_join(thread, NULL);
  producer_consumer_delete(pcqueue);
  printf("Pass\n");
  return 0;
}
