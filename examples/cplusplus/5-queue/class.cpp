#include <iostream>
#include <unistd.h>
#include <math.h>
#include <pthread.h>
#include <semaphore.h>
#include <string.h>

#define noinline __attribute__((noinline))
#define END_TOKEN (1 << 30)
#define END  10000000L

#define NUM_CONSUMERS 1
#define NUM_PRODUCERS 1

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

  void Push(T x);
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

template<int MAX, typename T>
Queue<MAX, T>::Queue(void)
  : head(0),
    tail(0)
{
  //memset(this, 0, sizeof(*this));

  int ret;

  ret = pthread_mutex_init(&lock, NULL);
  if (ret != 0) {
    throw "failed initializing mutex lock";
  }

  ret = sem_init(&empty, 0, 0);
  if (ret != 0) {
    throw "failed initializing semaphore";
  }

  ret = sem_init(&full, 0, MAX);
  if (ret != 0) {
    throw "failed initializing semaphore";
  }
}

template<int MAX, typename T>
Queue<MAX, T>::~Queue(void)
{
  int ret;

  ret = pthread_mutex_destroy(&lock);
  if (ret != 0) {
    throw "failed deinitializing lock";
  }

  ret = sem_destroy(&full);
  if (ret != 0) {
    throw "failed deinitializing semaphore";
  }

  ret = sem_destroy(&empty);
  if (ret != 0) {
    throw "failed deinitializing semaphore";
  }
}

// Will be livepatched.
template <int MAX, typename T>
void Queue<MAX, T>::Push(T x)
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

template <int MAX, typename T>
T Queue<MAX, T>::Pop(void)
{
  T ret;

  /* Block if the queue is empty.  */
  if (sem_wait(&empty) != 0) {
    throw "semaphore wait error";
  }

  /* Acquire lock of queue.  */
  if (pthread_mutex_lock(&lock) != 0) {
    throw "mutex lock error";
  }

  /* ----------------------------- */

  ret = elem[tail++];

  /* Wraps around if end of buffer.  */
  if (tail >= MAX) {
    tail = 0;
  }

  /* ----------------------------- */

  /* Release lock of queue.  */
  if (pthread_mutex_unlock(&lock) != 0) {
    throw "mutex unlock error";
  }

  /* Alert other threads that we inserted something.  */
  if (sem_post(&full) != 0) {
    throw "semaphore post error";
  }

  return ret;
}

void *consumer(void *p)
{
  Queue<QMAX, long> *q = (Queue<QMAX, long> *) p;
  long x;

  while ((x = q->Pop()) != END_TOKEN) {
  }

  return nullptr;
}

void *producer(void *p)
{
  Queue<QMAX, long> *q = (Queue<QMAX, long> *) p;

  for (long i = 0; i < END; i++) {
    q->Push(i);
  }
  q->Push(END_TOKEN);

  return nullptr;
}

int long_queue(void)
{
  Queue<QMAX, long> q;
  pthread_t producers[NUM_PRODUCERS];
  pthread_t consumers[NUM_CONSUMERS];

  for (int i = 0; i < NUM_PRODUCERS; i++) {
    if (pthread_create(&producers[i], NULL, producer, (void*) &q) != 0) {
      std::cout << "Error creating producer thread " << i << '\n';
      return 1;
    }
  }

  for (int i = 0; i < NUM_CONSUMERS; i++) {
    if (pthread_create(&consumers[i], NULL, consumer, (void*) &q) != 0) {
      std::cout << "Error creating consumer thread " << i << '\n';
      return 1;
    }
  }

  for (int i = 0; i < NUM_PRODUCERS; i++) {
    if (pthread_join(producers[i], NULL) != 0) {
      std::cout << "Error joining producer thread " << i << '\n';
      return 1;
    }
  }

  for (int i = 0; i < NUM_CONSUMERS; i++) {
    if (pthread_join(consumers[i], NULL) != 0) {
      std::cout << "Error joining consumers thread " << i << '\n';
      return 1;
    }
  }

  return 0;
}


void *consumer_dbl(void *p)
{
  Queue<QMAX, double> *q = (Queue<QMAX, double> *) p;
  double x;

  while ((x = q->Pop()) != (1./0.)) {
  }

  return nullptr;
}

void *producer_dbl(void *p)
{
  Queue<QMAX, double> *q = (Queue<QMAX, double> *) p;

  for (long i = 0; i < END; i++) {
    q->Push((double)i);
  }
  q->Push((double)(1./0.));

  return nullptr;
}

int double_queue(void)
{
  Queue<QMAX, double> q;
  pthread_t producers[NUM_PRODUCERS];
  pthread_t consumers[NUM_CONSUMERS];

  for (int i = 0; i < NUM_PRODUCERS; i++) {
    if (pthread_create(&producers[i], NULL, producer_dbl, (void*) &q) != 0) {
      std::cout << "Error creating producer thread " << i << '\n';
      return 1;
    }
  }

  for (int i = 0; i < NUM_CONSUMERS; i++) {
    if (pthread_create(&consumers[i], NULL, consumer_dbl, (void*) &q) != 0) {
      std::cout << "Error creating consumer thread " << i << '\n';
      return 1;
    }
  }

  for (int i = 0; i < NUM_PRODUCERS; i++) {
    if (pthread_join(producers[i], NULL) != 0) {
      std::cout << "Error joining producer thread " << i << '\n';
      return 1;
    }
  }

  for (int i = 0; i < NUM_CONSUMERS; i++) {
    if (pthread_join(consumers[i], NULL) != 0) {
      std::cout << "Error joining consumers thread " << i << '\n';
      return 1;
    }
  }

  return 0;
}

int main(void)
{
  long_queue();
  double_queue();
  return 0;
}
