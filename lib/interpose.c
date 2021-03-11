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
#include <assert.h>
#include <dlfcn.h>
#include <err.h>
#include <fcntl.h>
#include <libelf.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static int flag = 0;

/* Memory allocation functions. */
static void (*real_free)(void *) = NULL;
static void *(*real_malloc)(size_t) = NULL;
static void *(*real_calloc)(size_t, size_t) = NULL;
static void *(*real_realloc)(void *, size_t) = NULL;
static void *(*real_reallocarray)(void *, size_t, size_t) = NULL;
static void *(*real_valloc)(size_t) = NULL;
static void *(*real_pvalloc)(size_t) = NULL;
static void *(*real_memalign)(size_t, size_t) = NULL;
static void *(*real_aligned_alloc)(size_t, size_t) = NULL;
static int (*real_posix_memalign)(void **, size_t, size_t) = NULL;

/* Dynamic loader functions. */
static void *(*real_dlopen)(const char *, int) = NULL;
static void *(*real_dlmopen)(Lmid_t, const char *, int) = NULL;
static void *(*real_dlsym)(void *, const char *) = NULL;
static void *(*real_dlvsym)(void *, const char *, const char *) = NULL;
static int (*real_dlclose)(void *) = NULL;
static int (*real_dladdr)(const void *, Dl_info *) = NULL;
static int (*real_dladdr1)(const void *, Dl_info *, void **, int) = NULL;
static int (*real_dlinfo)(void *, int, void *) = NULL;

static Elf *elf;

/*
 * Finds and returns the section identified by NAME. Returns NULL if no
 * such section is found. Exits in error if the string table containing
 * sections names is not found.
 */
Elf_Scn *
find_section_by_name(char *name)
{
  char *str;
  size_t string_table;

  Elf_Scn *result;
  Elf_Scn *section;
  Elf64_Shdr *shdr;

  if (elf_getshdrstrndx(elf, &string_table) == -1)
    errx(1, "Unable to find the string table.\n");

  /* Iterate over all sections */
  result = NULL;
  section = NULL;
  while ((section = elf_nextscn(elf, section)) != NULL) {
    shdr = elf64_getshdr(section);

    str = elf_strptr(elf, string_table, shdr->sh_name);
    if (strcmp(name, str) == 0) {
      result = section;
      break;
    }
  }

  return result;
}

/*
 * Searches for a symbol named NAME. Returns a pointer to the Elf64_Sym
 * record that represents that symbol, or NULL if the symbol has not
 * been found.
 */
Elf64_Sym *
find_symbol_by_name(char *name)
{
  char *str;
  size_t entry_size;
  Elf_Scn *scn;
  Elf_Data *data;
  Elf64_Shdr *shdr;
  Elf64_Sym *sym;

  /* Use the .symtab if available, otherwise fallback to the .dynsym. */
  scn = find_section_by_name(".symtab");
  if (scn == NULL)
    scn = find_section_by_name(".dynsym");
  assert(scn);

  /* Iterate over the entries in the selected symbol table. */
  data = elf_getdata(scn, NULL);
  shdr = elf64_getshdr(scn);
  assert(data);
  assert(shdr);
  entry_size = sizeof(Elf64_Sym);
  for (size_t i = 0; i < shdr->sh_size; i += entry_size) {
    sym = (Elf64_Sym *)(data->d_buf + i);
    str = elf_strptr(elf, shdr->sh_link, sym->st_name);
    if (strcmp(name, str) == 0) {
      return sym;
    }
  }

  /* Symbol not found, return NULL. */
  return NULL;
}

/*
 * Searches for a symbol named NAME. Returns its address or zero if the
 * symbols is not found.
 */
Elf64_Addr
find_symbol_addr_by_name(char *name)
{
  Elf64_Sym *sym;

  sym = find_symbol_by_name(name);

  if (sym == NULL)
    return 0;

  return sym->st_value;
}

void *
get_dlsym_offset(char *path)
{
  int fd;
  Elf64_Addr result;

  fd = open(path, O_RDONLY);
  if (fd == -1)
    errx(EXIT_FAILURE, "Unable to open file '%s'.\n", path);

  elf_version(EV_CURRENT);
  elf = elf_begin(fd, ELF_C_READ, NULL);

  result = find_symbol_addr_by_name("dlsym");

  elf_end(elf);
  close(fd);

  if (result == 0)
    return NULL;
  return (void *)result;
}

static void *
get_dlsym_addr(void)
{
  FILE *fp;
  char line[PATH_MAX];
  char path[PATH_MAX];
  char *found;
  char *retcode;
  void *result;
  size_t length;
  long long base;

  fp = fopen("/proc/self/maps", "r");
  assert(fp);

  /* Look for libdl*.so in /proc/self/maps. */
  found = NULL;
  do {
    retcode = fgets(line, sizeof(line), fp);
    if (retcode == NULL)
      break;
    found = strstr(line, "libdl.so");
    if (found)
      break;
    found = strstr(line, "libdl-");
    if (found)
      break;
  }
  while (line[0]);

  if (found == NULL)
    return NULL;

  /* Copy the full path of libdl.so into PATH. */
  found = strstr(line, "/");
  if (found == NULL)
    return NULL;
  retcode = strncpy(path, found, sizeof(path) - 1);
  length = strnlen(path, sizeof(path));
  if (path[length - 1] == '\n')
    path[length - 1] = '\0';

  /* Find the in-file offset that dlsym has in libdl.so. */
  result = get_dlsym_offset(path);

  /* Add the in-memory base address of libdl to the in-file offset. */
  base = strtoll(line, NULL, 16);
  result += base;

  fclose(fp);
  return result;
}

__attribute__((constructor)) void
__ulp_asunsafe_begin(void)
{
  /*
   * If the address of dlsym is know (real_dlsym not NULL) this function
   * has already been executed successfully and learned the real
   * addresses of all interposed function, so do not run it again.
   */
  if (real_dlsym)
    return;

  /*
   * Calling dlsym to interpose dlsym itself is not possible, so take
   * advantage of the fact that, during process start up, DSOs are
   * available in-disk, find the file for libdl.so, open and parse it
   * with libelf, then find the in-memory address of dlsym. Doing this
   * from a constructor work even if the in-disk file changes or gets
   * deleted afterwards.
   */
  real_dlsym = (typeof(real_dlsym))get_dlsym_addr();
  assert(real_dlsym);

  real_dlopen = dlsym(RTLD_NEXT, "dlopen");
  real_dlmopen = dlsym(RTLD_NEXT, "dlmopen");
  real_dlvsym = dlsym(RTLD_NEXT, "dlvsym");
  real_dlclose = dlsym(RTLD_NEXT, "dlclose");
  real_dladdr = dlsym(RTLD_NEXT, "dladdr");
  real_dladdr1 = dlsym(RTLD_NEXT, "dladdr1");
  real_dlinfo = dlsym(RTLD_NEXT, "dlinfo");

  assert(real_dlopen);
  assert(real_dlmopen);
  assert(real_dlvsym);
  assert(real_dlclose);
  assert(real_dladdr);
  assert(real_dladdr1);
  assert(real_dlinfo);

  real_free = dlsym(RTLD_NEXT, "free");
  real_malloc = dlsym(RTLD_NEXT, "malloc");
  real_calloc = dlsym(RTLD_NEXT, "calloc");
  real_realloc = dlsym(RTLD_NEXT, "realloc");
  real_reallocarray = dlsym(RTLD_NEXT, "reallocarray");
  real_valloc = dlsym(RTLD_NEXT, "valloc");
  real_pvalloc = dlsym(RTLD_NEXT, "pvalloc");
  real_memalign = dlsym(RTLD_NEXT, "memalign");
  real_aligned_alloc = dlsym(RTLD_NEXT, "aligned_alloc");
  real_posix_memalign = dlsym(RTLD_NEXT, "posix_memalign");

  assert(real_free);
  assert(real_malloc);
  assert(real_calloc);
  assert(real_realloc);
  assert(real_reallocarray);
  assert(real_valloc);
  assert(real_pvalloc);
  assert(real_memalign);
  assert(real_aligned_alloc);
  assert(real_posix_memalign);
}

int
__ulp_asunsafe_trylock(void)
{
  int local;

  local = __sync_val_compare_and_swap(&flag, 0, 1);
  if (local)
    return 1;
  return 0;
}

int
__ulp_asunsafe_unlock(void)
{
  __sync_fetch_and_and(&flag, 0);
  return 0;
}

void
free(void *ptr)
{
  if (real_free == NULL) {
    munmap(ptr, 1);
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
    result = mmap(NULL, size, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
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
    result = mmap(NULL, nmemb * size, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
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

  if (real_realloc == NULL)
    __ulp_asunsafe_begin();

  __sync_fetch_and_add(&flag, 1);
  result = real_realloc(ptr, size);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

void *
reallocarray(void *ptr, size_t nmemb, size_t size)
{
  void *result;

  if (real_reallocarray == NULL)
    __ulp_asunsafe_begin();

  __sync_fetch_and_add(&flag, 1);
  result = real_reallocarray(ptr, nmemb, size);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

void *
valloc(size_t size)
{
  void *result;

  if (real_valloc == NULL)
    __ulp_asunsafe_begin();

  __sync_fetch_and_add(&flag, 1);
  result = real_valloc(size);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

void *
pvalloc(size_t size)
{
  void *result;

  if (real_pvalloc == NULL)
    __ulp_asunsafe_begin();

  __sync_fetch_and_add(&flag, 1);
  result = real_pvalloc(size);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

void *
memalign(size_t alignment, size_t size)
{
  void *result;

  if (real_memalign == NULL)
    __ulp_asunsafe_begin();

  __sync_fetch_and_add(&flag, 1);
  result = real_memalign(alignment, size);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

void *
aligned_alloc(size_t alignment, size_t size)
{
  void *result;

  if (real_aligned_alloc == NULL)
    __ulp_asunsafe_begin();

  __sync_fetch_and_add(&flag, 1);
  result = real_aligned_alloc(alignment, size);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

int
posix_memalign(void **memptr, size_t alignment, size_t size)
{
  int result;

  if (real_posix_memalign == NULL)
    __ulp_asunsafe_begin();

  __sync_fetch_and_add(&flag, 1);
  result = real_posix_memalign(memptr, alignment, size);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

void *
dlopen(const char *filename, int flags)
{
  void *result;

  if (real_dlopen == NULL)
    __ulp_asunsafe_begin();

  __sync_fetch_and_add(&flag, 1);
  result = real_dlopen(filename, flags);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

void *
dlmopen(Lmid_t nsid, const char *file, int mode)
{
  void *result;

  if (real_dlmopen == NULL)
    __ulp_asunsafe_begin();

  __sync_fetch_and_add(&flag, 1);
  result = real_dlmopen(nsid, file, mode);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

void *
dlsym(void *handle, const char *name)
{
  void *result;

  if (real_dlsym == NULL)
    __ulp_asunsafe_begin();

  __sync_fetch_and_add(&flag, 1);
  result = real_dlsym(handle, name);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

void *
dlvsym(void *handle, const char *name, const char *version)
{
  void *result;

  if (real_dlvsym == NULL)
    __ulp_asunsafe_begin();

  __sync_fetch_and_add(&flag, 1);
  result = real_dlvsym(handle, name, version);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

int
dlclose(void *handle)
{
  int result;

  if (real_dlclose == NULL)
    __ulp_asunsafe_begin();

  __sync_fetch_and_add(&flag, 1);
  result = real_dlclose(handle);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

int
dladdr(const void *address, Dl_info *info)
{
  int result;

  if (real_dladdr == NULL)
    __ulp_asunsafe_begin();

  __sync_fetch_and_add(&flag, 1);
  result = real_dladdr(address, info);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

int
dladdr1(const void *address, Dl_info *info, void **extra_info, int flags)
{
  int result;

  if (real_dladdr1 == NULL)
    __ulp_asunsafe_begin();

  __sync_fetch_and_add(&flag, 1);
  result = real_dladdr1(address, info, extra_info, flags);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}

int
dlinfo(void *handle, int request, void *arg)
{
  int result;

  if (real_dlinfo == NULL)
    __ulp_asunsafe_begin();

  __sync_fetch_and_add(&flag, 1);
  result = real_dlinfo(handle, request, arg);
  __sync_fetch_and_sub(&flag, 1);

  return result;
}
