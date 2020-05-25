#ifdef DEBUG
# include <stdio.h>
# define INFO(format, ...) \
    fprintf(stderr, "ulp: " format "\n", ##__VA_ARGS__)
#else
# define INFO(...)
#endif

#include <errno.h>
#include <strings.h>
#include <sys/mman.h>
#include <unistd.h>

#include <ulp/alloc.h>
#include <ulp/alloc-internal.h>

/*
 * Libulp has its own arenas for memory allocation, where it keeps an
 * array of heaps (contiguous regions of memory), which are mmaped on an
 * as-needed basis. The DEFAULT arena is supposed to be used to allocate
 * memory for the detours, which never get freed, whereas the SCRATCH
 * arena is suppose to be used to temporarily allocate memory for
 * parsing metadata files and should be cleared right after livepatches
 * have been applied or checked.
 */
struct ulp_arena __ulp_default_arena = {0};
struct ulp_arena __ulp_scratch_arena = {0};

/* Fetch the size of a page from sysconf during startup. */
__attribute__ ((constructor)) void ulp_alloc_constructor(void)
{
  __ulp_default_arena.page_size = sysconf (_SC_PAGESIZE);
  __ulp_scratch_arena.page_size = sysconf (_SC_PAGESIZE);
}

/*
 * Initializes the semaphores of the default and scratch arenas. Should
 * be called during program startup, but only once, because calling
 * sem_init on an already initialized semaphore invokes undefined
 * behavior. Returns 0 on success and 1 on error.
 */
int
ulp_arena_init (void)
{
  int ret;
  struct ulp_arena *arena;

  arena = get_default_arena ();
  ret = sem_init (&arena->semaphore, 0, 1);
  if (ret) {
    perror ("Unable to initialize default arena semaphore.");
    return 1;
  }

  arena = get_scratch_arena ();
  ret = sem_init (&arena->semaphore, 0, 1);
  if (ret) {
    perror ("Unable to initialize scratch arena semaphore.");
    return 1;
  }

  return 0;
}

/*
 * Tries to acquire the lock on both arenas. This function returns
 * immediately (does not block). Returns 0 on success, which means that
 * both arenas are locked by the calling thread. Otherwise, return 1 and
 * release any locks it has acquired in the process.
 */
int
ulp_arena_trylock (void)
{
  struct ulp_arena *default_arena;
  struct ulp_arena *scratch_arena;

  default_arena = get_default_arena ();
  scratch_arena = get_scratch_arena ();

  /* Try to acquire the lock to the default arena. */
  if (sem_trywait (&default_arena->semaphore))
    return 1;

  /*
   * Try to acquire the lock to the scratch arena. If it fails, restore
   * the lock it just acquired on the default arena.
   */
  if (sem_trywait (&scratch_arena->semaphore)) {
    sem_post (&default_arena->semaphore);
    return 1;
  }

  return 0;
}

/* Unlocks the semaphores to both ulp arenas. Always returns 0. */
int
ulp_arena_unlock (void)
{
  struct ulp_arena *default_arena;
  struct ulp_arena *scratch_arena;

  default_arena = get_default_arena ();
  scratch_arena = get_scratch_arena ();

  sem_post (&default_arena->semaphore);
  sem_post (&scratch_arena->semaphore);

  return 0;
}

/*
 * Allocates SIZE bytes of memory within the ulp arena pointed to by
 * ARENA, which cannot be NULL.
 *
 * Returns the absolute address of the allocated memory, or NULL if
 * errors occurred. If BASE *and* OFFSET are not null, writes this same
 * address to them, but split into the address of the start of the
 * current allocation page and the offset within that page.
 *
 * Typically, within libulp, this function is not called directly, but
 * rather by ulp_default_alloc() or ulp_scratch_alloc(), which choose
 * the appropriate arena, depending on the usage scenario.
 *
 * WARNING: Cannot allocate more bytes than what fits on a single page
 *          size. However, even small pages are big compared to the
 *          amount of memory that libulp allocates at a time.
 */
void *
ulp_alloc (struct ulp_arena *arena, int size, void **base, long *offset)
{
  int i;
  int value;
  void *new;
  struct ulp_heap *heap;

  if (arena == NULL)
    return NULL;

  /* Check for arena lock. */
  if (sem_getvalue (&arena->semaphore, &value)) {
    perror ("Unable to read current arena semaphore.");
    return NULL;
  }
  if (value != 0) {
    INFO ("Trying to allocate memory without holding a lock.");
    return NULL;
  }

  if (size > arena->page_size) {
    INFO ("Cannot allocate more bytes than fit on a single page.");
    return NULL;
  }

  /*
   * Iterate over all heaps in ARENA and try to find a free slot. If one
   * is available, write its address to 'new'.
   */
  new = NULL;
  for (i = 0; i < arena->available_heaps; i++) {
    heap = &arena->heaps[i];
    /* Break at the first uninitialized heap */
    if (heap->base == NULL)
      break;
    /* Break if the current heap has enough memory available. */
    if (heap->offset + size < arena->page_size) {
      new = heap->base + heap->offset;
      break;
    }
  }

  /*
   * If a suitable location was found, 'new' would have been set to its
   * absolute address, which is the final return value. However, the
   * heap itself still needs updating.
   *
   * On the other hand, if no suitable location was found within the
   * previously initialized heaps, add a new heap to the arena.
   */
  if (new) {
    heap->offset += size;
  }
  else if (i < ULP_MAX_HEAPS) {
    new = mmap (NULL, arena->page_size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    /* If mmap fails, return NULL, as if no space was available. */
    if (new == MAP_FAILED) {
      INFO ("Failed to mmap a new page.");
      return NULL;
    }
    if (new == NULL) {
      INFO ("Unexpected NULL return from mmap.");
      return NULL;
    }
    /* Update the arena. */
    heap = &arena->heaps[i];
    heap->base = new;
    heap->offset = size;
    arena->available_heaps++;
  }

  /*
   * If new is still NULL, all attempts to allocate memory failed, this
   * is probably due to the fact that there are no more free slots in
   * the heap array.
   */
  if (new == NULL) {
    INFO ("No space left on the arena.");
    return NULL;
  }

  /* Finally, update the optional parameters: base and offset. */
  if (base && offset) {
    *base = heap->base;
    *offset = heap->offset - size;
  }

  /* Initialize data to zeros and return. */
  bzero (new, size);
  return new;
}

/*
 * Returns the address to the default arena, which is typically used to
 * allocate space for new detours during livepatch installation, and
 * typically never freed.
 */
struct ulp_arena *
get_default_arena (void)
{
  return &__ulp_default_arena;
}

/*
 * Returns the address to the scratch arena, which is typically used to
 * allocate space for metadata parsing during livepatch installation,
 * and typically completely freed afterwards.
 */
struct ulp_arena *
get_scratch_arena (void)
{
  return &__ulp_scratch_arena;
}

/*
 * Allocates SIZE bytes of space on the default arena. This function is
 * typically used when the allocated space is not supposed to be freed.
 * Returns a pointer to the allocated space, or NULL on error.
 */
void *
ulp_default_alloc (int size)
{
  return ulp_alloc (get_default_arena(), size, NULL, NULL);
}

/*
 * Allocates SIZE bytes of space on the scratch arena. This function is
 * typically used when the allocated space is only going to be used
 * briefly, during the parsing of the metadata file. Returns a pointer
 * to the allocated space, or NULL on error.
 */
void *
ulp_scratch_alloc (int size)
{
  return ulp_alloc (get_scratch_arena(), size, NULL, NULL);
}

/*
 * Frees all the data in ARENA, which cannot be NULL. All previous
 * memory allocations in this ARENA become invalid and may not be
 * accessed afterwards. Returns 0 on success.
 *
 * Typically, within libulp, this function is not called directly, but
 * rather by ulp_scratch_clear().
 */
int
ulp_clear_arena (struct ulp_arena *arena)
{
  int value;
  int i;
  struct ulp_heap *heap;

  if (arena == NULL)
    return 1;

  /* Check for arena lock. */
  if (sem_getvalue (&arena->semaphore, &value)) {
    perror ("Unable to read current arena semaphore.");
    return 1;
  }
  if (value != 0) {
    INFO ("Trying to clear arena without holding a lock.");
    return 1;
  }

  for (i = 0; i < arena->available_heaps; i++) {
    heap = &arena->heaps[i];
    if (munmap (heap->base, arena->page_size)) {
      INFO ("Failed to unmap head at %p\n", heap->base);
    }
    heap->base = NULL;
    heap->offset = 0;
  }
  arena->available_heaps = 0;

  return 0;
}

/*
 * Frees all the data in the scratch arena. All previous memory
 * allocations in the scratch arena become invalid and may not be
 * accessed afterwards. Returns 0 on success.
 *
 * This function is typically called when the previously-parsed,
 * livepatch metadata becomes no longer necessary.
 */
int
ulp_scratch_clear (void)
{
  return ulp_clear_arena (get_scratch_arena());
}
