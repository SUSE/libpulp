#include <errno.h>
#include <stdio.h>

#include <semaphore.h>

#include <ulp/alloc.h>
#include <ulp/alloc-internal.h>

int
main (void)
{
  int ret;
  int value;
  int *address;
  struct ulp_arena *default_arena;
  struct ulp_arena *scratch_arena;

  default_arena = get_default_arena ();
  scratch_arena = get_scratch_arena ();

  /* Initialization tests. */

  /* Test initial semaphore values (internal implementation). */
  if (sem_getvalue (&default_arena->semaphore, &value)) {
    perror ("Unable to read semaphore data.");
    return 1;
  }
  else if (value != 1) {
    printf ("Unexpected initial semaphore value.\n");
    return 1;
  }
  if (sem_getvalue (&scratch_arena->semaphore, &value)) {
    perror ("Unable to read semaphore data.");
    return 1;
  }
  else if (value != 1) {
    printf ("Unexpected initial semaphore value.\n");
    return 1;
  }

  /* Regular use tests. */

  /* Regular use of the arena lock acquisition. */
  if (ulp_arena_trylock ()) {
    printf ("Unable to acquire the locks on both arenas.\n");
    return 1;
  }

  /* Trying to acquire the lock again, should fail. */
  if (ulp_arena_trylock () == 0) {
    printf ("Unexpectedly acquired the lock twice.\n");
    return 1;
  }

  /* Valid use of the alloc functions while holding the lock. */
  address = ulp_default_alloc (1);
  if (address == NULL) {
    printf ("Unable to allocate on a locked arena.\n");
    return 1;
  }
  address = ulp_scratch_alloc (1);
  if (address == NULL) {
    printf ("Unable to allocate on a locked arena.\n");
    return 1;
  }
  ret = ulp_scratch_clear ();
  if (ret) {
    printf ("Unable to clear a locked arena.\n");
    return 1;
  }

  /* Regular release of the locks (never fails). */
  ulp_arena_unlock ();

  /* Invalid use of the alloc functions without holding the lock. */
  address = ulp_default_alloc (1);
  if (address != NULL) {
    printf ("Unexpectedly able to allocate on an unlocked arena.\n");
    return 1;
  }
  address = ulp_scratch_alloc (1);
  if (address != NULL) {
    printf ("Unexpectedly able to allocate on an unlocked arena.\n");
    return 1;
  }
  ret = ulp_scratch_clear ();
  if (ret == 0) {
    printf ("Unexpectedly able to clear an unlocked arena.\n");
    return 1;
  }

  /* Internal implementation tests. */

  /*
   * Acquire the locks to the default arena via sem_trywait (internal
   * implementation), then try to acquire the locks with the regular
   * interface, which should fail and leave the semaphore's states
   * untouched.
   */
  if (sem_trywait (&default_arena->semaphore)) {
    perror ("Unable to get a lock directly with sem_trywait.");
    return 1;
  }
  if (ulp_arena_trylock () == 0) {
    printf ("Unexpectedly acquired the lock.\n");
    return 1;
  }
  if (ulp_arena_trylock () == 0) {
    printf ("Retrying to acquire a lock unexpectedly succeeded.\n");
    return 1;
  }
  sem_post (&default_arena->semaphore);

  /* Likewise, but starting with the scratch arena. */
  if (sem_trywait (&scratch_arena->semaphore)) {
    perror ("Unable to get a lock directly with sem_trywait.");
    return 1;
  }
  if (ulp_arena_trylock () == 0) {
    printf ("Unexpectedly acquired the lock.\n");
    return 1;
  }
  if (ulp_arena_trylock () == 0) {
    printf ("Retrying to acquire a lock unexpectedly succeeded.\n");
    return 1;
  }
  sem_post (&scratch_arena->semaphore);

  return 0;
}
