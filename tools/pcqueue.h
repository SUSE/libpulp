#ifndef PCQUEUE_H
#define PCQUEUE_H

#include <pthread.h>
#include <semaphore.h>

/* Uncoment this if the producer_consumer queue should support multiple
   producers and consumers.  */
/* #define MORE_THAN_ONE_ONE  */

/** A producer-consumer queue.  This structure creates a channel in which
    two threads can communicate, one by enqueuing elements and another by
    dequeuing elements.  */
struct producer_consumer
{
  /** Maximum number of elements in this queue.  */
  int n;

  /** Position of the last inserted element.*/
  int head;

  /** Position of the oldest element in the queue.  */
  int tail;

  /** Semaphore that will block any attempt of dequeuing an element if the
      queue is empty.  */
  sem_t empty;

  /** Semaphore that will block any attempt of enqueuing an element if the
      queue is full.  */
  sem_t full;
#ifdef MORE_THAN_ONE_ONE
  /** Lock for head & tail.  This is unnecessary if there is only one producer
      and one consumer.  If you wish to support many producers and many
      consumers, define MORE_THAN_ONE_ONE.  */
  pthread_mutex_t lock;
#endif

  /** The queue buffer.  The 0 array element denotes where it starts, but it is
      allocated in `producer_consumer_new`.  */
  void *elem[0];
};

/** Typedef for a shorthand of struct producer_consumer.  */
typedef struct producer_consumer producer_consumer_t;

producer_consumer_t *producer_consumer_new(int n);

int producer_consumer_delete(producer_consumer_t *queue);

int producer_consumer_enqueue(producer_consumer_t *queue, void *elem);

void *producer_consumer_dequeue(producer_consumer_t *queue);

#endif // PCQUEUE_H
