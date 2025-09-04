/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2021 SUSE Software Solutions GmbH
 *
 *  This file is part of libpulp.
 *
 *  libpulp is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  libpulp is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with libpulp.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <err.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <gnu/libc-version.h>
#include <grp.h>
#include <limits.h>
#include <link.h>
#include <pthread.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/param.h>

#include "interpose.h"
#include "symbol_loader.h"
#include "config.h"
#include "ld_rtld.h"
#include "msg_queue.h"
#include "ulp.h"
#include "ulp_common.h"
#include "arch_common.h"

/* This header should be included last, as it poisons some symbols.  */
#include "error.h"

/* Declare internal glibc functions which are exposed. We have to use them
   while __ulp_asunsafe_begin have not run yet.  */
extern void __libc_free(void *);
extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void *__libc_valloc(size_t);
extern void *__libc_pvalloc(size_t);
extern void *__libc_memalign(size_t, size_t);
/* aligned_alloc doesn't have an alternate public symbol.  */
/* posix_memalign doesn't have an alternate public symbol.  */

static int flag = 0;

/* Memory allocation functions. */
static void (*real_free)(void *) = NULL;
static void *(*real_malloc)(size_t) = NULL;
static void *(*real_calloc)(size_t, size_t) = NULL;
static void *(*real_realloc)(void *, size_t) = NULL;
static void *(*real_valloc)(size_t) = NULL;
static void *(*real_pvalloc)(size_t) = NULL;
static void *(*real_memalign)(size_t, size_t) = NULL;
static void *(*real_aligned_alloc)(size_t, size_t) = NULL;
static int (*real_posix_memalign)(void **, size_t, size_t) = NULL;

/* Dynamic loader functions. */
static void *(*real_dlopen)(const char *, int) = NULL;
static void *(*real_dlmopen)(Lmid_t, const char *, int) = NULL;
static int (*real_dlclose)(void *) = NULL;
static int (*real_dladdr)(const void *, Dl_info *) = NULL;
static int (*real_dladdr1)(const void *, Dl_info *, void **, int) = NULL;
static int (*real_dlinfo)(void *, int, void *) = NULL;

/* Linker structures.  */
static pthread_mutex_t *dl_load_lock = NULL;
static pthread_mutex_t *dl_load_write_lock = NULL;

static bool
dl_locks_held(void)
{
  libpulp_assert(0 <= dl_load_lock->__data.__lock &&
                 dl_load_lock->__data.__lock <= 1);
  libpulp_assert(0 <= dl_load_write_lock->__data.__lock &&
                 dl_load_write_lock->__data.__lock <= 1);

  return (dl_load_lock->__data.__lock || dl_load_write_lock->__data.__lock);
}

// @brief Disable livepatching based on LIBPULP_DISABLE_ON_PATH variable.
//
// This function will scan the LIBPULP_DISABLE_ON_PATH variable for wildcards
// which would match the path to the program's binary.
//
// Example: LIBPULP_DISABLE_ON_PATH=/home/*:/tmp/*
//
// Would block livepatching any program launched from the /home or /tmp folder.
static void
maybe_disable_livepatching_on_path(void)
{
  const char *disabled_names = getenv("LIBPULP_DISABLE_ON_PATH");
  if (disabled_names == NULL) {
    return;
  }

  size_t len = strlen(disabled_names);

  char *names = malloc(len + 1);
  if (names == NULL) {
    set_libpulp_error_state(errno);
    return;
  }
  memcpy(names, disabled_names, len + 1);

  char process_path[PATH_MAX];
  ssize_t n = readlink("/proc/self/exe", process_path, sizeof(process_path));
  if ((size_t)n >= sizeof(process_path)) {
    WARN("Unable to get path to executable. Livepatching is disabled.");
    set_libpulp_error_state(EINITFAIL);
  }

  /* readlink do not append the '\0' character.  Do it now.  */
  process_path[n] = '\0';

  const char *wildcard;
  for (wildcard = strtok(names, ":"); wildcard != NULL;
       wildcard = strtok(NULL, ":")) {
    if (fnmatch(wildcard, process_path, FNM_EXTMATCH) == 0) {
      /* Match.  */
      set_libpulp_error_state(EUSRBLOCKED);
      WARN("Matched path pattern %s: livepatching disabled by user request.",
           wildcard);
      break;
    }
  }

  free(names);
}

/** @brief Disable livepatching based on LIBPULP_DISABLE_ON_USERS variable.
 *
 * This function will scan the LIBPULP_DISABLE_ON_USERS variable for wildcards
 * which would match the path to the user name or uid.
 *
 * Example: LIBPULP_DISABLE_ON_USERS=1000:root
 *
 * Would block livepatching any program launched from user 'root' or user with
 * uid = 1000.
 */
static void
maybe_disable_livepatching_on_user(void)
{
  const char *disabled_names = getenv("LIBPULP_DISABLE_ON_USERS");
  if (disabled_names == NULL) {
    return;
  }

  size_t len = strlen(disabled_names);

  char *names = malloc(len + 1);
  if (names == NULL) {
    set_libpulp_error_state(errno);
    return;
  }
  memcpy(names, disabled_names, len + 1);

  uid_t uid = getuid();
  struct passwd *pws = getpwuid(uid);
  const char *uname = pws ? pws->pw_name : NULL;

  const char *wildcard;
  for (wildcard = strtok(names, ":"); wildcard != NULL;
       wildcard = strtok(NULL, ":")) {
    if (isnumber(wildcard) && strtoul(wildcard, NULL, 10) == uid) {
      set_libpulp_error_state(EUSRBLOCKED);
      WARN("Matched uid %s: livepatching disabled by user request.", wildcard);
      break;
    }
    else if (uname != NULL) {
      if (fnmatch(wildcard, uname, FNM_EXTMATCH) == 0) {
        /* Match.  */
        set_libpulp_error_state(EUSRBLOCKED);
        WARN("Matched user pattern %s: livepatching disabled by user request.",
             wildcard);
        break;
      }
    }
  }

  free(names);
}

/** @brief Disable livepatching based on LIBPULP_DISABLE_ON_GROUPS variable.
 *
 * This function will scan the LIBPULP_DISABLE_ON_GROUPS variable for wildcards
 * which would match the path to the group name or group id.
 *
 * Example: LIBPULP_DISABLE_ON_USERS=1000:root
 *
 * Would block livepatching any program launched from user 'root' or user with
 * uid = 1000.
 */
static void
maybe_disable_livepatching_on_group(void)
{
  const char *disabled_names = getenv("LIBPULP_DISABLE_ON_GROUPS");
  if (disabled_names == NULL) {
    return;
  }

  size_t len = strlen(disabled_names);

  char *names = malloc(len + 1);
  if (names == NULL) {
    set_libpulp_error_state(errno);
    return;
  }
  memcpy(names, disabled_names, len + 1);

  gid_t gid = getgid();
  struct group *g = getgrgid(gid);
  const char *gname = g ? g->gr_name : NULL;

  const char *wildcard;
  for (wildcard = strtok(names, ":"); wildcard != NULL;
       wildcard = strtok(NULL, ":")) {
    if (isnumber(wildcard) && strtoul(wildcard, NULL, 10) == gid) {
      set_libpulp_error_state(EUSRBLOCKED);
      WARN("Matched gid %s: livepatching disabled by user request.", wildcard);
      break;
    }
    else if (gname != NULL) {
      if (fnmatch(wildcard, gname, FNM_EXTMATCH) == 0) {
        /* Match.  */
        set_libpulp_error_state(EUSRBLOCKED);
        WARN(
            "Matched group pattern %s: livepatching disabled by user request.",
            wildcard);
        break;
      }
    }
  }

  free(names);
}

__attribute__((constructor)) void
__ulp_asunsafe_begin(void)
{
  /*
   * If the address of dlsym is know (real_malloc not NULL) this function
   * has already been executed successfully and learned the real
   * addresses of all interposed function, so do not run it again.
   */
  if (real_malloc)
    return;

  bool ok = true;

  real_dlopen = dlsym(RTLD_NEXT, "dlopen");
  real_dlmopen = dlsym(RTLD_NEXT, "dlmopen");
  real_dlclose = dlsym(RTLD_NEXT, "dlclose");
  real_dladdr = dlsym(RTLD_NEXT, "dladdr");
  real_dladdr1 = dlsym(RTLD_NEXT, "dladdr1");
  real_dlinfo = dlsym(RTLD_NEXT, "dlinfo");

  /* Check if we got the symbols we need from libdl.  */
  if (!real_dlopen) {
    set_libpulp_error_state_with_reason(ENOLIBDL, "unable to find function `dlopen`.");
    ok = false;
  }

  if (!real_dlmopen) {
    set_libpulp_error_state_with_reason(ENOLIBDL, "unable to find function `dlmopen`.");
    ok = false;
  }

  if (!real_dlclose) {
    set_libpulp_error_state_with_reason(ENOLIBDL, "unable to find function `dlclose`.");
    ok = false;
  }

  if (!real_dladdr) {
    set_libpulp_error_state_with_reason(ENOLIBDL, "unable to find function `dladdr`.");
    ok = false;
  }

  if (!real_dladdr1) {
    set_libpulp_error_state_with_reason(ENOLIBDL, "unable to find function `dladdr1`.");
    ok = false;
  }

  if (!real_dlinfo) {
    set_libpulp_error_state_with_reason(ENOLIBDL, "unable to find function `dlinfo`.");
    ok = false;
  }

  real_free = dlsym(RTLD_NEXT, "free");
  real_malloc = dlsym(RTLD_NEXT, "malloc");
  real_calloc = dlsym(RTLD_NEXT, "calloc");
  real_realloc = dlsym(RTLD_NEXT, "realloc");
  real_valloc = dlsym(RTLD_NEXT, "valloc");
  real_pvalloc = dlsym(RTLD_NEXT, "pvalloc");
  real_memalign = dlsym(RTLD_NEXT, "memalign");
  real_aligned_alloc = dlsym(RTLD_NEXT, "aligned_alloc");
  real_posix_memalign = dlsym(RTLD_NEXT, "posix_memalign");

  /* Check if we got the symbols we need from glibc.  */
  if (!real_free) {
    set_libpulp_error_state_with_reason(ENOLIBC, "unable to find function `free`.");
    ok = false;
  }

  if (!real_malloc) {
    set_libpulp_error_state_with_reason(ENOLIBC, "unable to find function `malloc`.");
    ok = false;
  }

  if (!real_calloc) {
    set_libpulp_error_state_with_reason(ENOLIBC, "unable to find function `calloc`.");
    ok = false;
  }

  if (!real_realloc) {
    set_libpulp_error_state_with_reason(ENOLIBC, "unable to find function `realloc`.");
    ok = false;
  }

  if (!real_pvalloc) {
    set_libpulp_error_state_with_reason(ENOLIBC, "unable to find function `pvalloc`.");
    ok = false;
  }

  if (!real_memalign) {
    set_libpulp_error_state_with_reason(ENOLIBC, "unable to find function `memalign`.");
    ok = false;
  }

  if (!real_aligned_alloc) {
    set_libpulp_error_state_with_reason(ENOLIBC, "unable to find function `aligned_alloc`.");
    ok = false;
  }

  if (!real_posix_memalign) {
    set_libpulp_error_state_with_reason(ENOLIBC, "unable to find function `posix_memalign`");
    ok = false;
  }

  if (ok == false)
    return;

  /* Initialize dynamic linker load and write lock, used by dlsym.  */
  get_ld_global_locks(&dl_load_lock, &dl_load_write_lock);

  /* Check if we got acceptable values from the lock.  If not, that means we
     probably have a bad glibc version and therefore it is better to disable
     livepatching altogether.  */
  dl_locks_held();

  maybe_disable_livepatching_on_path();
  maybe_disable_livepatching_on_user();
  maybe_disable_livepatching_on_group();
}

/** @brief Lock the `flag` lock to indicate that this process in being patched.
 *
 * This function will lock the `flag` lock, which indicates that this process
 * is being analyzed by libpulp tools.  This runs when the thread was hijacked.
 *
 * @return   0 if lock was not held, 1 if held.
 */
int
__ulp_asunsafe_trylock(void)
{
  int local;
  if (dl_locks_held())
    return 1;

  local = __sync_val_compare_and_swap(&flag, 0, 1);
  if (local)
    return 1;
  return 0;
}

/** @brief Unlock the `flag` lock.  */
int
__ulp_asunsafe_unlock(void)
{
  __sync_fetch_and_and(&flag, 0);
  return 0;
}

/* Interposed functions.  */

void
free(void *ptr)
{
  if (real_free == NULL) {
    __libc_free(ptr);
    return;
  }

  __sync_fetch_and_add(&flag, 1);
  real_free(ptr);
  __sync_fetch_and_sub(&flag, 1);
}

void *
malloc(size_t size)
{
  void *result;

  if (real_malloc == NULL) {
    result = __libc_malloc(size);
    return result;
  }

  __sync_fetch_and_add(&flag, 1);
  result = real_malloc(size);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

void *
calloc(size_t nmemb, size_t size)
{
  void *result;

  if (real_calloc == NULL) {
    result = __libc_calloc(nmemb, size);
    return result;
  }

  __sync_fetch_and_add(&flag, 1);
  result = real_calloc(nmemb, size);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

void *
realloc(void *ptr, size_t size)
{
  void *result;

  if (real_realloc == NULL) {
    return __libc_realloc(ptr, size);
  }

  __sync_fetch_and_add(&flag, 1);
  result = real_realloc(ptr, size);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

void *
valloc(size_t size)
{
  void *result;

  if (real_valloc == NULL) {
    return __libc_valloc(size);
  }

  __sync_fetch_and_add(&flag, 1);
  result = real_valloc(size);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

void *
pvalloc(size_t size)
{
  void *result;

  if (real_pvalloc == NULL) {
    return __libc_pvalloc(size);
  }

  __sync_fetch_and_add(&flag, 1);
  result = real_pvalloc(size);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

void *
memalign(size_t alignment, size_t size)
{
  void *result;

  if (real_memalign == NULL) {
    return __libc_memalign(alignment, size);
  }

  __sync_fetch_and_add(&flag, 1);
  result = real_memalign(alignment, size);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

void *
aligned_alloc(size_t alignment, size_t size)
{
  void *result;

  if (real_aligned_alloc == NULL) {
    /* We have to emulate this function using memalign.  */
    if ((alignment & (alignment - 1)) || (size & (alignment - 1))) {
      errno = EINVAL;
      return NULL;
    }

    return  __libc_memalign(alignment, size);
  }

  __sync_fetch_and_add(&flag, 1);
  result = real_aligned_alloc(alignment, size);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

int
posix_memalign(void **memptr, size_t alignment, size_t size)
{
  int result;

  if (real_posix_memalign == NULL) {
    void *mem;

    /* Implement posix_memalign using memalign.  */
    if (alignment % sizeof (void *) != 0
        || !powerof2 (alignment / sizeof (void *))
        || alignment == 0)
      return EINVAL;

    mem = __libc_memalign(alignment, size);

    if (mem != NULL) {
      *memptr = mem;
      return 0;
    }

    return ENOMEM;
  }

  __sync_fetch_and_add(&flag, 1);
  result = real_posix_memalign(memptr, alignment, size);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

void *
dlopen(const char *filename, int flags)
{
  void *result;

  if (real_dlopen == NULL) {
    __ulp_asunsafe_begin();
  }

  __sync_fetch_and_add(&flag, 1);
  result = real_dlopen(filename, flags);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

void *
dlmopen(Lmid_t nsid, const char *file, int mode)
{
  void *result;

  if (real_dlmopen == NULL) {
    __ulp_asunsafe_begin();
  }

  __sync_fetch_and_add(&flag, 1);
  result = real_dlmopen(nsid, file, mode);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

int
dlclose(void *handle)
{
  int result;

  if (real_dlclose == NULL) {
    __ulp_asunsafe_begin();
  }

  __sync_fetch_and_add(&flag, 1);
  result = real_dlclose(handle);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

int
dladdr(const void *address, Dl_info *info)
{
  int result;

  if (real_dladdr == NULL) {
    __ulp_asunsafe_begin();
  }

  __sync_fetch_and_add(&flag, 1);
  result = real_dladdr(address, info);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

int
dladdr1(const void *address, Dl_info *info, void **extra_info, int flags)
{
  int result;

  if (real_dladdr1 == NULL) {
    __ulp_asunsafe_begin();
  }

  __sync_fetch_and_add(&flag, 1);
  result = real_dladdr1(address, info, extra_info, flags);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

int
dlinfo(void *handle, int request, void *arg)
{
  int result;

  if (real_dlinfo == NULL) {
    __ulp_asunsafe_begin();
  }

  __sync_fetch_and_add(&flag, 1);
  result = real_dlinfo(handle, request, arg);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}
