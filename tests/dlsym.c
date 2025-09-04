#define _GNU_SOURCE
#include "../include/config.h"
#include "../include/ld_rtld.h"
#include <dlfcn.h>
#include <gnu/lib-names.h>
#include <gnu/libc-version.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define WARN(format, ...) fprintf(stderr, "ulp: " format "\n", ##__VA_ARGS__)
#define libpulp_errx(a, ...) fprintf(stderr, __VA_ARGS__); abort();

void __attribute__((noreturn))
libpulp_crash(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end (args);

  abort();
}

static volatile pthread_mutex_t *dl_load_lock = NULL;
static volatile pthread_mutex_t *dl_load_write_lock = NULL;

#include "../lib/symbol_loader.c"

static volatile int gate = 0;

void *
observer(void *args __attribute__((unused)))
{
  while (1) {
    int lock = dl_load_lock->__data.__lock;
    if (lock == 1) {
      printf("dl lock was acquired: %d\n", lock);
      gate = 1;
      return (void *)0;
    }
    else if (lock < 0 || lock > 1) {
      printf("dl lock is nonsensical: %d\n", lock);
      return (void *)1;
    }
  }

  return (void *)1;
}

void *
dlsym_poke(void *args __attribute__((unused)))
{
  while (!gate) {
    dlsym(RTLD_DEFAULT, "malloc");
  }

  return NULL;
}

int
main()
{
  unsigned long observer_ret;
  get_ld_global_locks((void *) &dl_load_lock, (void *) &dl_load_write_lock);

  pthread_t observer_thread, dlsym_thread;

  pthread_create(&observer_thread, NULL, observer, NULL);
  pthread_create(&dlsym_thread, NULL, dlsym_poke, NULL);

  pthread_join(observer_thread, (void *)&observer_ret);
  pthread_join(dlsym_thread, NULL);
  return (int)observer_ret;
}
