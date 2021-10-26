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
#include <limits.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* This header should be included last, as it poisons some symbols.  */
#include "error.h"

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

/** @brief Get symbol by its name
 *
 * Example: calling this function with name = 'printf' will return
 * the ELF symbol referring to the printf function.
 *
 * @param dynsym: The symbol table.
 * @param dynstr: The symbol string table.
 * @param len: The length of dynsym
 * @param name: Name of the symbol to search.
 *
 * @return a pointer to the wanted symbol in the symbol table.
 */
static Elf64_Sym *
get_symbol_by_name(Elf64_Sym dynsym[], const char *dynstr, int len,
                   const char *name)
{
  int i;
  for (i = 0; i < len; i++) {
    /* st_name contains the offset of the symbol's name on the dynstr table. */
    if (!strcmp(dynstr + dynsym[i].st_name, name))
      return &dynsym[i];
  }

  /* Symbol not found.  */
  return NULL;
}

/** struct containing the parameters that will be passed to dl_find_symbol.  */
struct dl_iterate_arg
{
  const char *library; /* Name of the .so file to find the symbol. */
  const char *symbol;  /* The name of the wanted symbol. */

  void *symbol_addr; /* The address of the symbol in the program. */
};

/** @brief dl_iterate_phdr callback.
 *
 * This function do the hard work into gathering the necessary informations
 * about the symbols in the process. It works by being a callback to
 * dl_iterate_phdr (read its manpage), which pass into "info" the ELF program
 * headers (phdr) of:
 *  1. The current binary.
 *  2. Each dynamic library (.so) loaded with the program.
 *
 * Then it parses the structures there to find the .dynsym, .dynstr, and .hash
 * sections containing respectively:
 *
 *  1. The dynamic symbol table.
 *  2. The symbol string table with the name of each symbol.
 *  3. The hash table (only used to find the number of symbol in .dynsym).
 *
 * The library name which we want to find its symbol, and the wanted symbol
 * is passed on struct dl_iterate_arg, which is passed on the "data" argument.
 * If library name is NULL, this function will find the first occurence of
 * "symbol" in the entire program. The output of this function is also written
 * on the struct pointed by "data", and it is a pointer to the symbol in the
 * program.
 *
 * Good references to understeand how to parse the ELF program headers are:
 *  1. The elf.h header.
 *  2. 'dl_iterate_phdr' manpage.
 *  3. 'Learing Linux Binary Analysis' (Elfmaster, 2016).
 *  4. 'Linkers and Loaders' (Levine, 1999).
 *
 * @param info: Program header infos (see dl_iterate_phdr).
 * @param size: sizeof(dl_phdr_info).
 * @param data: Data to this function. Also used as return value.
 *
 * @return 1 when done; 0 to request next library.
 */
static int
dl_find_symbol(struct dl_phdr_info *info, size_t size, void *data)
{
  /* We call the symbol table as dynsym because that is most likely to be the
   * section in DT_SYMTAB.  However, this is not necessary true in all cases.
   */
  Elf64_Sym *dynsym = NULL;
  const char *dynstr = NULL;
  int *hash_addr;

  int i;
  int num_symbols = 0;
  struct dl_iterate_arg *args = (struct dl_iterate_arg *)data;

  /* Sanity check if size matches the size of the struct.  */
  if (size != sizeof(*info)) {
    libpulp_errx(EXIT_FAILURE, "dl_phdr_info size is unexpected");
    return 0;
  }

  /* Initialize output value as being NULL (symbol not found).  */
  args->symbol_addr = NULL;

  /* Check if the current info is the library we want to find the symbols.  */
  if (args->library && !strstr(info->dlpi_name, args->library))
    return 0;

  /* Pointers to linux-vdso.so are invalid, so skip this library.  */
  if (!strcmp(info->dlpi_name, "linux-vdso.so.1"))
    return 0;

  /* Iterate each program headers to find the information we need. */
  for (i = 0; i < info->dlpi_phnum; i++) {
    const Elf64_Phdr *phdr_addr = &info->dlpi_phdr[i];

    /* We are interested in symbols, so look for the dynamic symbols in the
     * PT_DYNAMIC tag. */
    if (phdr_addr->p_type == PT_DYNAMIC) {

      /* The address in p_paddr is relative to the .so header, so we need to
       * add the base address where the .so was mapped in the process. In case
       * it is the binary itself, dlpi_addr is zero.  */
      Elf64_Dyn *dyn = (Elf64_Dyn *)(info->dlpi_addr + phdr_addr->p_paddr);

      /* Iterate over each tag in this section.  */
      for (; dyn->d_tag != DT_NULL; dyn++) {
        switch (dyn->d_tag) {
          case DT_SYMTAB:
            dynsym = (Elf64_Sym *)dyn->d_un.d_ptr;
            break;

          case DT_STRTAB:
            dynstr = (const char *)dyn->d_un.d_ptr;
            break;

          case DT_SYMENT:
            /* This section stores the size of a symbol entry. So compare it
             * with the size of Elf64_Sym as a sanity check.  */
            if (dyn->d_un.d_val != sizeof(Elf64_Sym)) {
              libpulp_errx(EXIT_FAILURE, "DT_SYMENT value of %s is unexpected",
                           info->dlpi_name);
              return 0;
            }
            break;

          case DT_HASH:
            /* Look at the hash section for the number of the symbols in the
             * symbol table.  This section structure in memory is:
             *
             * hash_t nbuckets;
             * hash_t nchains;
             * hash_t buckets[nbuckets];
             * hash_t chain[nchains];
             *
             * hash_t is either int32_t or int64_t according to the arch.
             * On x86_64 it is 32-bits.
             * */
            hash_addr = (int *)dyn->d_un.d_ptr;
            num_symbols = hash_addr[1]; /* Get nchains.  */
            break;
        }
      }
    }
  }

  /* With the symbol table identified, find the wanted symbol.  */
  if (dynstr && dynsym) {
    Elf64_Sym *sym;

    sym = get_symbol_by_name(dynsym, dynstr, num_symbols, args->symbol);
    if (sym)
      args->symbol_addr = (void *)(info->dlpi_addr + sym->st_value);

    /* Alert dl_iterate_phdr that we are finished.  */
    return 1;
  }
  return 0;
}

/** @brief Get the address of a loaded symbol from library.
 *
 * This function will return the address where the symbol with the name
 * "symbol" from the library "library" was allocated in memory.
 *
 * Example: calling this function with symbol = "printf" will return
 * the address where the printf function is.
 *
 * @param library: name of the library where the symbol is from.
 * @param symbol: name of the wanted symbol
 *
 * @return the address where the symbol was allocated nn the program.
 */
void *
get_loaded_symbol_addr(const char *library, const char *symbol)
{
  struct dl_iterate_arg arg = { .library = library, .symbol = symbol };
  dl_iterate_phdr(dl_find_symbol, &arg);

  return arg.symbol_addr;
}

static int
dl_find_base_addr(struct dl_phdr_info *info, size_t size, void *data)
{
  struct dl_iterate_arg *args = (struct dl_iterate_arg *)data;

  /* Highly improvable that any library will have this base address.  */
  args->symbol_addr = (void *)0xFF;

  /* Sanity check if size matches the size of the struct.  */
  if (size != sizeof(*info)) {
    libpulp_errx(EXIT_FAILURE, "dl_phdr_info size is unexpected");
    return 0;
  }

  /* Pointers to linux-vdso.so are invalid, so skip this library.  */
  if (!strcmp(info->dlpi_name, "linux-vdso.so.1"))
    return 0;

  /* Check if the current info is the library we want to find the symbols.  */
  if (*info->dlpi_name != '\0' && strstr(info->dlpi_name, args->library)) {
    /* Found.  Set symbol_addr as the base address of library.  */
    args->symbol_addr = (void *)info->dlpi_addr;

    /* Alert dl_iterate that we are finished.  */
    return 1;
  }

  return 0;
}

void *
get_loaded_library_base_addr(const char *library)
{
  struct dl_iterate_arg arg = { .library = library };
  dl_iterate_phdr(dl_find_base_addr, &arg);

  return arg.symbol_addr;
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
   * Calling dlsym to interpose dlsym itself is not possible, so look
   * at the loaded dynamic symbols from "libdl.so" for the "dlsym" function.
   */
  real_dlsym = (typeof(real_dlsym))get_loaded_symbol_addr("libdl.so", "dlsym");
  if (!real_dlsym) {
    /* Check if that is present in libc.  */
    real_dlsym =
        (typeof(real_dlsym))get_loaded_symbol_addr("libc.so", "dlsym");
  }

  libpulp_crash_assert(real_dlsym);

  real_dlopen = dlsym(RTLD_NEXT, "dlopen");
  real_dlmopen = dlsym(RTLD_NEXT, "dlmopen");
  real_dlvsym = dlsym(RTLD_NEXT, "dlvsym");
  real_dlclose = dlsym(RTLD_NEXT, "dlclose");
  real_dladdr = dlsym(RTLD_NEXT, "dladdr");
  real_dladdr1 = dlsym(RTLD_NEXT, "dladdr1");
  real_dlinfo = dlsym(RTLD_NEXT, "dlinfo");

  libpulp_crash_assert(real_dlopen);
  libpulp_crash_assert(real_dlmopen);
  libpulp_crash_assert(real_dlvsym);
  libpulp_crash_assert(real_dlclose);
  libpulp_crash_assert(real_dladdr);
  libpulp_crash_assert(real_dladdr1);
  libpulp_crash_assert(real_dlinfo);

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

  libpulp_crash_assert(real_free);
  libpulp_crash_assert(real_malloc);
  libpulp_crash_assert(real_calloc);
  libpulp_crash_assert(real_realloc);
  libpulp_crash_assert(real_reallocarray);
  libpulp_crash_assert(real_valloc);
  libpulp_crash_assert(real_pvalloc);
  libpulp_crash_assert(real_memalign);
  libpulp_crash_assert(real_aligned_alloc);
  libpulp_crash_assert(real_posix_memalign);
  libpulp_crash_assert(real_posix_memalign);
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
