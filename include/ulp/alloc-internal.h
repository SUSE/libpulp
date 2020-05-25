#include <semaphore.h>

#define ULP_MAX_HEAPS 300

struct ulp_heap {
  void *base;
  long offset;
};

struct ulp_arena {
  struct ulp_heap heaps[ULP_MAX_HEAPS];
  int available_heaps;
  long page_size;

  sem_t semaphore;
};

void *
ulp_alloc (struct ulp_arena *arena, int size, void **base, long *offset);

struct ulp_arena *
get_default_arena (void);

struct ulp_arena *
get_scratch_arena (void);

int
ulp_clear_arena (struct ulp_arena *arena);
