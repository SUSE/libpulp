#include <semaphore.h>
#include <pthread.h>
#include <iostream>

#define QMAX 32

/** A producer-consumer queue.  This structure creates a channel in which
    two threads can communicate, one by enqueuing elements and another by
    dequeuing elements.  */
template<int MAX, typename T>
class Queue
{
  public:
  Queue(void);
  ~Queue(void);

  void Push_LP(T x);
  T Pop(void);

  protected:
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

  /** Lock for head & tail.  This is unnecessary if there is only one producer
      and one consumer.  If you wish to support many producers and many
      consumers, define MORE_THAN_ONE_ONE.  */
  pthread_mutex_t lock;

  /** The queue buffer.  */
  T elem[MAX];
};

static bool already_print_l = false;
static bool already_print_d = false;

template <int MAX, typename T>
void Queue<MAX, T>::Push_LP(T x)
{
  int ret;
  /* Block if the queue is full.  */
  ret = sem_wait(&full);
  if (ret != 0) {
    throw "semaphore error";
  }

  /* Acquire lock of queue.  */
  ret = pthread_mutex_lock(&lock);
  if (ret != 0) {
    throw "mutex lock error";
  }
  /* ----------------------------- */

  if (typeid(T) == typeid(long) && already_print_l == false) {
    std::cout << "from critical section with type long\n";
    already_print_l = true;
  } else if (typeid(T) == typeid(double) && already_print_d == false) {
    std::cout << "from critical section with type double\n";
    already_print_d = true;
  }

  elem[head++] = x;

  /* Wraps around if end of buffer.  */
  if (head >= MAX) {
    head = 0;
  }

  /* ----------------------------- */

  /* Release lock of queue.  */
  ret = pthread_mutex_unlock(&lock);
  if (ret != 0) {
    throw "mutex release error";
  }

  /* Alert other threads that we inserted something.  */
  ret = sem_post(&empty);
  if (ret != 0) {
    throw "semaphore post error";
  }
}

/* Output the modified functions for all types generated.  */
template void Queue<QMAX, long>::Push_LP(long x);
template void Queue<QMAX, double>::Push_LP(double x);
