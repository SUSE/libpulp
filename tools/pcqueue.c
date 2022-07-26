#include "pcqueue.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** @brief Initialize the producer_consumer object.
 *
 * This function is for internal use only.  Call `producer_consumer_new` if
 * you want to create a producer_consumer object.
 *
 * @param queue   The queue to initialize
 * @param n       Maximum number of objects in this queue.
 * @return        0 if success, anything else if error.
 */
static int
producer_consumer_init(producer_consumer_t *queue, int n)
{
  int ret;
  memset(queue, 0, sizeof(*queue));

  queue->n = n;
#ifdef MORE_THAN_ONE_ONE
  ret = pthread_mutex_init(&queue->lock, NULL);
  if (ret != 0) {
    return ret;
  }
#endif
  ret = sem_init(&queue->empty, 0, 0);
  if (ret != 0) {
    return errno;
  }

  ret = sem_init(&queue->full, 0, n);
  if (ret != 0) {
    return errno;
  }

  return 0;
}

/** @brief Create a new producer_consumer object.
 *
 * This function allocates memory and initializes a producer_consumer object.
 * Call `producer_consumer_delete` if you wish to deinitialize and free all
 * the resources allocated there.
 *
 * @param n       Maximum number of objects in this queue.
 *
 * @return        Pointer to the created producer_consumer object.
 */
producer_consumer_t *
producer_consumer_new(int n)
{
  producer_consumer_t *q;
  size_t size = sizeof(producer_consumer_t) + n * sizeof(void *);

  q = (producer_consumer_t *)malloc(size);

  if (q == NULL)
    return NULL;

  if (producer_consumer_init(q, n)) {
    free(q);
    q = NULL;
  }
  return q;
}

/** @brief Initialize the producer_consumer object.
 *
 * This function is for internal use only.  Call `producer_consumer_delete` if
 * you want to release a producer_consumer object.
 *
 * @param queue   The queue to destroy.
 *
 * @return        0 if success, anything else if error.
 */
static int
producer_consumer_destroy(producer_consumer_t *queue)
{
  int ret;

#ifdef MORE_THAN_ONE_ONE
  ret = pthread_mutex_destroy(&queue->lock);
  if (ret != 0) {
    return ret;
  }
#endif

  ret = sem_destroy(&queue->full);
  if (ret != 0) {
    return errno;
  }

  ret = sem_destroy(&queue->empty);
  if (ret != 0) {
    return errno;
  }

  memset(queue, 0, sizeof(*queue));
  return 0;
}

/** @brief Deinitialize and release all resources of `queue`;
 *
 * Call this function if you wish to release all resources allocated to a
 * producer_consumer object.
 *
 * @param queue   The queue to destroy.
 *
 * @return        0 if success, anything else if error.
 */
int
producer_consumer_delete(producer_consumer_t *queue)
{
  int ret = 0;
  if (queue != NULL) {
    ret = producer_consumer_destroy(queue);
    free(queue);
  }

  return ret;
}

/** @brief Enqueue an `elem` to the queue.
 *
 * Call this function if you wish to enqueue the object `elem` to the queue.
 *
 * @param queue   The queue to insert.
 * @param elem    The element to insert.
 *
 * @return        0 if success, anything else if error.
 */
int
producer_consumer_enqueue(producer_consumer_t *queue, void *elem)
{
  int ret;
  /* Block if the queue is full.  */
  ret = sem_wait(&queue->full);
  if (ret != 0) {
    return errno;
  }

#ifdef MORE_THAN_ONE_ONE
  /* Acquire lock of queue.  */
  ret = pthread_mutex_lock(&queue->lock);
  if (ret != 0) {
    return ret;
  }
#endif
  /* ----------------------------- */

  queue->elem[queue->head++] = elem;

  /* Wraps around if end of buffer.  */
  if (queue->head >= queue->n) {
    queue->head = 0;
  }

  /* ----------------------------- */

#ifdef MORE_THAN_ONE_ONE
  /* Release lock of queue.  */
  ret = pthread_mutex_unlock(&queue->lock);
  if (ret != 0) {
    return ret;
  }
#endif

  /* Alert other threads that we inserted something.  */
  ret = sem_post(&queue->empty);
  if (ret != 0) {
    return errno;
  }

  return 0;
}

/** @brief Dequeue an element from producer_consumer `queue`.
 *
 * Call this function if you wish to dequeue an element from the queue.
 *
 * @param queue   The queue to get an element from.
 * @return        The dequeued element.
 */
void *
producer_consumer_dequeue(producer_consumer_t *queue)
{
  void *ret;

  /* Block if the queue is empty.  */
  if (sem_wait(&queue->empty) != 0) {
    return NULL;
  }

#ifdef MORE_THAN_ONE_ONE
  /* Acquire lock of queue.  */
  if (pthread_mutex_lock(&queue->lock) != 0) {
    return NULL;
  }
#endif

  /* ----------------------------- */

  ret = queue->elem[queue->tail++];

  /* Wraps around if end of buffer.  */
  if (queue->tail >= queue->n) {
    queue->tail = 0;
  }

  /* ----------------------------- */

#ifdef MORE_THAN_ONE_ONE
  /* Release lock of queue.  */
  if (pthread_mutex_unlock(&queue->lock) != 0) {
    return NULL;
  }
#endif

  /* Alert other threads that we inserted something.  */
  if (sem_post(&queue->full) != 0) {
    return NULL;
  }

  return ret;
}
