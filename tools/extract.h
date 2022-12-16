#ifndef _EXTRACT_H_
#define _EXTRACT_H_

#include "arguments.h"
#include "ulp_common.h"

#include <stdbool.h>
#include <stdio.h>
#include <link.h>
#include <libelf.h>

/** Struct containing useful information for Userspace Livepatching retrieved
 *  from the target .so file.
 */
struct symbol
{
  /** Name of the symbol (function, variable).  */
  const char *name;

  /** Offset of such symbol.  */
  ElfW(Addr) offset;

  /** Size of symbol.  */
  Elf32_Word size;

  /** Symbol visibility.  See elf.h.  */
  unsigned char st_info;

  /** Symbol type and binding.  See elf.h.  */
  unsigned char st_other;

  /** Next symbol in the symbol table chain.  */
  struct symbol *next;
};

/** Struct containing the useful information for userspace livepatching
 *  retrieved from the .so file.
 */
struct ulp_so_info
{
  /** Name of the library.  Empty for none.  */
  const char *name;

  /** Build ID for library.  Zero for unitialized.  */
  unsigned char buildid[BUILDID_LEN];

  /** List of symbols extracted from the target library.  */
  struct symbol *symbols;
};

void release_so_info(struct ulp_so_info *);

void release_symbol(struct symbol *symbol);

void write_ulp_so_info_json(FILE *stream, const struct ulp_so_info *info);

struct symbol *build_symbols_list(Elf *elf);

struct ulp_so_info *parse_so_elf(const char *target_path);

bool so_info_equal(struct ulp_so_info *a, struct ulp_so_info *b);

struct ulp_so_info *parse_so_json(const char *path);

void dump_ulp_so_info(const struct ulp_so_info *info);

struct symbol *get_symbol_with_name(struct ulp_so_info *info, const char *sym);

int run_extract(struct arguments *arguments);

struct ulp_so_info *ulp_so_info_open(const char *path);

#endif /* _EXTRACT_H_.  */
