#define _GNU_SOURCE
#include "../include/ld_rtld.h"
#include <dlfcn.h>
#include <gnu/lib-names.h>
#include <gnu/libc-version.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *rtld_global = NULL;
static volatile pthread_mutex_t *dl_load_lock = NULL;
static volatile pthread_mutex_t *dl_load_write_lock = NULL;

/** struct containing the parameters that will be passed to dl_find_symbol.  */
struct dl_iterate_arg
{
  /* Input.  */

  /** Name of the .so file to find the symbol. */
  const char *library;

  /** The name of the wanted symbol. */
  const char *symbol;

  /* Output.  */

  /** The address of the symbol in the program. */
  void *symbol_addr;

  /** The address bias where the library was loaded.  */
  uintptr_t bias_addr;

  /** The TLS module index of the library.  */
  int tls_index;
};

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
    abort();
    return 0;
  }

  /* Initialize output value as being NULL (symbol not found).  */
  args->symbol_addr = NULL;

  /* Initialize TLS index with invalid value.  */
  args->tls_index = -1;

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
              abort();
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
    args->tls_index = info->dlpi_tls_modid;

    sym = get_symbol_by_name(dynsym, dynstr, num_symbols, args->symbol);
    if (sym)
      args->symbol_addr = (void *)(info->dlpi_addr + sym->st_value);

    args->bias_addr = info->dlpi_addr;
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
 * @param old_faddr: Offset of symbol, as found during packing.
 *
 * @return the address where the symbol was allocated nn the program.
 */
void *
get_loaded_symbol_addr(const char *library, const char *symbol,
                       void *old_faddr)
{
  /* Check if the current info is the program's binary itself.  In that case
   * we must handle things somewhat differently.  */
  if (library == NULL) {
    library = "";
  }

  struct dl_iterate_arg arg = { .library = library, .symbol = symbol };
  dl_iterate_phdr(dl_find_symbol, &arg);

  if (old_faddr != NULL && arg.symbol_addr != old_faddr) {
    printf("Symbol requested not found in .dymsym. Using address from .ulp\n");
    return arg.bias_addr + old_faddr;
  }

  return arg.symbol_addr;
}

static void
get_ld_global_locks()
{
  char libc_ver[32];
  const char *tok;
  int major, minor;

  rtld_global = get_loaded_symbol_addr(LD_SO, "_rtld_global", NULL);

  if (!rtld_global) {
    fprintf(stderr, "symbol _rtld_global not found in ld-linux-x86_64.so\n");
    abort();
  }

  strcpy(libc_ver, gnu_get_libc_version());

  tok = strtok(libc_ver, ".");
  major = atoi(tok);
  tok = strtok(NULL, ".");
  minor = atoi(tok);

  if (major == 2) {
    if (31 <= minor && minor < 35) {
      struct rtld_global__2_31 *rtld = rtld_global;
      dl_load_lock = &rtld->_dl_load_lock.mutex;
      dl_load_write_lock = &rtld->_dl_load_write_lock.mutex;
    }
    else if (35 <= minor) {
      struct rtld_global__2_35 *rtld = rtld_global;
      dl_load_lock = &rtld->_dl_load_lock.mutex;
      dl_load_write_lock = &rtld->_dl_load_write_lock.mutex;
    }
    else {
      fprintf(stderr, "glibc version %d.%d is unsupported\n", major, minor);
      abort();
    }
  }
}

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
  get_ld_global_locks();

  pthread_t observer_thread, dlsym_thread;

  pthread_create(&observer_thread, NULL, observer, NULL);
  pthread_create(&dlsym_thread, NULL, dlsym_poke, NULL);

  pthread_join(observer_thread, (void *)&observer_ret);
  pthread_join(dlsym_thread, NULL);
  return (int)observer_ret;
}
