/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017-2023 SUSE Software Solutions GmbH
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

#include <assert.h>
#include <errno.h>
#include <json-c/json.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "arguments.h"
#include "config.h"
#include "elf-extra.h"
#include "extract.h"
#include "packer.h"
#include "terminal_colors.h"
#include "ulp_common.h"

/** @brief Convert a string to a build id.
 *
 * This function converts the buildid in string form provided by str
 * and write its buildid form in the buffer provided by `buf`.
 *
 * @param buf     Buffer to write to.
 * @param str     Input string.
 *
 * @return        EINVAL if string is invalid, 0 otherwise.
 */
static int
str_to_buildid(unsigned char buf[BUILDID_LEN], const char *str)
{
  int i;

  if (strlen(str) < BUILDID_LEN) {
    /* Invalid buildid given.  */
    return EINVAL;
  }

  for (i = 0; i < BUILDID_LEN; i++) {
    unsigned val;
    sscanf(&str[2 * i], "%02x", &val);

    buf[i] = (unsigned char)val;
  }

  return 0;
}

/* clang-format off */

/** Table mapping ST_TYPE values to its name.  */
static const char *const st_type_names[] = {
  /*  0 = */ "STT_NOTYPE",
  /*  1 = */ "STT_OBJECT",
  /*  2 = */ "STT_FUNC",
  /*  3 = */ "STT_SECTION",
  /*  4 = */ "STT_FILE",
  /*  5 = */ "STT_COMMON",
  /*  6 = */ "STT_TLS",
  /*  7 = */ "STT_NUM",
  /*  8 = */ NULL,
  /*  9 = */ NULL,
  /* 10 = */ "STT_GNU_IFUNC",
  /* 11 = */ NULL,
  /* 12 = */ "STT_HIOS",
  /* 13 = */ "STT_LOPROC",
  /* 14 = */ NULL,
  /* 15 = */ "STT_HIPROC",
};

/** Table mapping ST_BIND values to its name.  */
static const char *const st_bind_names[] = {
  /*  0 = */ "STB_LOCAL",
  /*  1 = */ "STB_GLOBAL",
  /*  2 = */ "STB_WEAK",
  /*  3 = */ "STB_NUM",
  /*  4 = */ "STB_FILE",
  /*  5 = */ NULL,
  /*  6 = */ NULL,
  /*  7 = */ NULL,
  /*  8 = */ NULL,
  /*  9 = */ NULL,
  /* 10 = */ "STB_GNU_UNIQUE",
  /* 11 = */ NULL,
  /* 12 = */ "STB_HIOS",
  /* 13 = */ "STB_LOPROC",
  /* 14 = */ NULL,
  /* 15 = */ "STB_HIPROC",
};

static const char *const stv_visibility_names[] = {
  /* 0 =  */ "STV_DEFAULT",
  /* 1 =  */ "STV_INTERNAL",
  /* 2 =  */ "STV_HIDDEN",
  /* 3 =  */ "STV_PROTECTED",
};

/* clang-format on */

/** Get ST_TYPE name according to its value.  */
#define GET_ST_TYPE_NAME(s) st_type_names[ELF64_ST_TYPE(s)]

/** Get ST_BIND name according to its value.  */
#define GET_ST_BIND_NAME(s) st_bind_names[ELF64_ST_BIND(s)]

/** Get STV_VISIBILITY name according to its value.  */
#define GET_STV_VISIBILITY_NAME(s) stv_visibility_names[ELF64_ST_VISIBILITY(s)]

/** @brief dump symbol
 *
 * Dump a struct symbol to stdout for debugging purposes.
 *
 */
static void
dump_symbol(const struct symbol *symbol)
{
  FILE *o = stdout;
  while (symbol) {
    fprintf(o, "  symbols: 0x%lx\n", (unsigned long)symbol);
    fprintf(o, "    name    : %s\n", symbol->name);
    fprintf(o, "    offset  : 0x%lx\n", symbol->offset);
    fprintf(o, "    size    : 0x%d\n", symbol->size);
    fprintf(o, "    st_info : %u\n", (unsigned)symbol->st_info);
    fprintf(o, "      type  : %s\n", GET_ST_TYPE_NAME(symbol->st_info));
    fprintf(o, "      bind  : %s\n", GET_ST_BIND_NAME(symbol->st_info));
    fprintf(o, "    st_other: %u\n", (unsigned)symbol->st_other);
    fprintf(o, "      visibi: %s\n",
            GET_STV_VISIBILITY_NAME(symbol->st_other));

    symbol = symbol->next;
  }
}

/** @brief dump ulp_so_info
 *
 * Dump a struct ulp_so_info to stdout for debugging purposes.
 *
 */
void
dump_ulp_so_info(const struct ulp_so_info *info)
{
  fprintf(stdout, "ulp_so_info: 0x%lx\n", (uintptr_t)info);
  fprintf(stdout, "  name: %s\n", info->name);
  fprintf(stdout, "  buildid: %s\n", buildid_to_string(info->buildid));
  dump_symbol(info->symbols);
}

/** Shorthand to create a new JSON string.  */
#define JSTR(x) json_object_new_string(x)

/** Shorthand to create a new JSON int.  */
#define JINT(x) json_object_new_int(x)

/** @brief Get a JSON object representing a symbol.
 *
 * Output the symbol structure as a JSON node.
 *
 * @param symbol    symbol object.
 *
 * @return json object representing symbol.
 */
static json_object *
get_json_symbol(const struct symbol *symbol)
{
  json_object *js = json_object_new_object();

  assert(js && "Could not create json object.");

  json_object_object_add(js, "name", JSTR(symbol->name));
  json_object_object_add(js, "offset", JINT(symbol->offset));
  json_object_object_add(js, "size", JINT(symbol->size));
  json_object_object_add(js, "st_info", JINT(symbol->st_info));
  json_object_object_add(js, "st_other", JINT(symbol->st_other));

  return js;
}

/** @brief Output ulp_so_info structure in JSON form.
 *
 * Dumps the `ulp_so_info` in JSON format to the `stream`.
 *
 * @param stream    The file stream to be output.
 * @param info      The ulp_so_info object.
 */
void
write_ulp_so_info_json(FILE *stream, const struct ulp_so_info *info)
{
  /* Create root JSON object.  */
  json_object *root = json_object_new_object();

  /* Assert that we got the root.  */
  assert(root && "Error allocating root JSON object.");

  /* Create a library object that will hold the content of one library.  */
  json_object *library = json_object_new_object();

  /* Add the interesting stuff there.  */
  json_object_object_add(library, "name", JSTR(info->name));
  json_object_object_add(library, "buildid",
                         JSTR(buildid_to_string(info->buildid)));

  /* Add the list of symbols.  */
  json_object *symbols = json_object_new_array();
  struct symbol *symbol;
  for (symbol = info->symbols; symbol != NULL; symbol = symbol->next) {
    json_object *jsymbol = get_json_symbol(symbol);

    /* Add a single symbol to the array of symbols.  */
    json_object_array_add(symbols, jsymbol);
  }

  /* Add array of symbols to the library.  */
  json_object_object_add(library, "symbols", symbols);

  /* Add library to the root of JSON tree.  */
  json_object_object_add(root, "library", library);

  fputs(json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY), stream);

  /* Release stuff.  */
  json_object_put(root);
}

/** @brief Get a list of symbols on given section.
 *
 * Given an elf object and a symbol table section (dynsym or symtab), compute
 * the list of symbols in this section.
 *
 * @param elf       The elf object.
 * @param s         The section to list the symbols.
 *
 * @return          The list of symbols. NULL if something goes wrong.
 */
static struct symbol *
get_list_of_symbols_in_section(Elf *elf, Elf_Scn *s)
{
  struct symbol *symbol_head = NULL;

  int nsyms, i;
  char *sym_name;
  Elf_Data *data;
  GElf_Shdr sh;
  GElf_Sym sym;

  gelf_getshdr(s, &sh);

  nsyms = sh.sh_size / sh.sh_entsize;
  data = elf_getdata(s, NULL);
  if (!data) {
    return NULL;
  }

  for (i = 0; i < nsyms; i++) {
    gelf_getsym(data, i, &sym);
    sym_name = elf_strptr(elf, sh.sh_link, sym.st_name);

    /* Do not include symbols that seems invalid.  */
    if (*sym_name == '\0') {
      continue;
    }

    struct symbol *symbol = calloc(1, sizeof(struct symbol));
    symbol->name = strdup(sym_name);
    symbol->offset = sym.st_value;
    symbol->size = sym.st_size;
    symbol->st_info = sym.st_info;
    symbol->st_other = sym.st_other;

    symbol->next = symbol_head;
    symbol_head = symbol;
  }
  return symbol_head;
}

/** @brief Build list of symbols in the elf object.
 *
 * The ELF object have a list of exported symbols and may have a list of
 * private symbols in their .dynsym and .symtab sections, respectivelly.
 * This function will list all symbols from both sections and return a list
 * with all of them.
 *
 * @param elf    The elf object
 *
 * @return       A list containing all symbols in the elf object.
 */
struct symbol *
build_symbols_list(Elf *elf)
{
  /* Get the externalized symbols.  */
  Elf_Scn *dynsym = get_dynsym(elf);

  /* Get the private symbols.  */
  Elf_Scn *symtab = get_symtab(elf);

  /* Iterate on the dynsym first and list all symbols there.  */
  struct symbol *symbols_dynsym = get_list_of_symbols_in_section(elf, dynsym);
  struct symbol *symbols_symtab = get_list_of_symbols_in_section(elf, symtab);

  /* Merge both lists.  */
  struct symbol **it = &symbols_dynsym;
  for (; *it != NULL; it = &(*it)->next)
    ;
  *it = symbols_symtab;

  return symbols_dynsym;
}

/** @brief Open target .so file and collect all useful information for
 *  livepatching purposes.
 *
 *  This function will open the .so file and parse the ELF file and collect
 *  the information we need in order to create a livepatch, such as the
 *  library name, build id, and list of symbols.
 */
struct ulp_so_info *
parse_so_elf(const char *target_path)
{
  if (target_path == NULL)
    return NULL;

  /* Load ELF.  */
  int fd;
  Elf *elf = load_elf(target_path, &fd);
  struct ulp_so_info *so_info = NULL;

  /* Create the ulp_so_info object.  */
  so_info = calloc(1, sizeof(struct ulp_so_info));
  if (so_info == NULL) {
    WARN("Memory allocation error\n");
    goto clean_elf;
  }

  /* Load the build id of elf object.  */
  unsigned buildid_len = 0;
  if (get_elf_buildid(elf, (char *)so_info->buildid, &buildid_len)) {
    WARN("Elf in %s do not have a build id.", target_path);
    FREE_AND_NULLIFY(so_info);
    goto clean_elf;
  }

  if (buildid_len != BUILDID_LEN) {
    WARN("Build ID len doesn't match BUILDID_LEN macro");
    FREE_AND_NULLIFY(so_info);
    goto clean_elf;
  }

  /* Get library name.  */
  so_info->name = strdup(get_basename(target_path));

  /* Build list of symbols.  */
  so_info->symbols = build_symbols_list(elf);

clean_elf:
  unload_elf(&elf, &fd);
  return so_info;
}

/** @brief Parse json_object containing symbols array.
 *
 * When parsing the JSON input file, this function grabs the object
 * containing the symbols array and return the list of struct symbols
 * that can be used by packer.
 *
 * @param symbol_array             Object containing the array of symbols.
 *
 * @return struct symbol list of symbols, or NULL if an error occured.
 */
static struct symbol *
parse_symbols_json(json_object *symbol_array)
{
  array_list *array = json_object_get_array(symbol_array);
  size_t len = json_object_array_length(symbol_array);

  if (array == NULL || len == 0) {
    /* No symbols or invalid JSON.  */
    return NULL;
  }

  struct symbol *first = NULL;
  struct symbol *current = first;

  for (size_t i = 0; i < len; i++) {
    json_object *obj = array->array[i];

    json_object *jname = json_object_object_get(obj, "name");
    json_object *joffset = json_object_object_get(obj, "offset");
    json_object *jsize = json_object_object_get(obj, "size");
    json_object *jst_info = json_object_object_get(obj, "st_info");
    json_object *jst_other = json_object_object_get(obj, "st_other");

    const char *name = strdup(json_object_get_string(jname));
    Elf64_Addr offset = json_object_get_int(joffset);
    size_t size = json_object_get_int(jsize);
    unsigned char st_info = (unsigned char)json_object_get_int(jst_info);
    unsigned char st_other = (unsigned char)json_object_get_int(jst_other);

    struct symbol *new = calloc(1, sizeof(struct symbol));
    assert(new && "Error allocating a new symbol element.");

    new->name = name;
    new->offset = offset;
    new->size = size;
    new->st_info = st_info;
    new->st_other = st_other;

    /* Append to the symbols linked list.  */
    if (current == NULL) {
      current = new;
      first = new;
    }
    else {
      current->next = new;
      current = new;
    }
  }

  return first;
}

/** @brief Compare two ulp_so_info to find if they are equal
 *
 * Do a deep analysis to find this.
 *
 * @return 0 if equal, anything else if not.
 */
bool
so_info_equal(struct ulp_so_info *a, struct ulp_so_info *b)
{
  if (strcmp(a->name, b->name) != 0) {
    return false;
  }

  if (memcmp(a->buildid, b->buildid, BUILDID_LEN) != 0) {
    return false;
  }

  struct symbol *a_cur = a->symbols;
  struct symbol *b_cur = b->symbols;

  while (a_cur && b_cur) {
    if (strcmp(a_cur->name, b_cur->name) != 0 ||
        a_cur->offset != b_cur->offset || a_cur->size != b_cur->size ||
        a_cur->st_info != b_cur->st_info ||
        a_cur->st_other != b_cur->st_other) {
      return false;
    }

    a_cur = a_cur->next;
    b_cur = b_cur->next;
  }

  /* If we are here and they are equal, then both of them is NULL.  */
  if (a_cur == NULL && b_cur == NULL) {
    return true;
  }

  /* This means there are more stuff in one of the lists and therefore is not
     equal.  */

  return false;
}

/** @brief Load the relevant so data which was stored in JSON format.
 *
 * After the .so file was parsed and its relevant content dumped in a JSON
 * format, this function reads the JSON to reload the ulp_so_info structure so
 * that it can be used by packer later.
 *
 * @param path          Path to the JSON file.
 *
 * @return              The ulp_so_info structure from the JSON, or NULL in
 * case of error.
 */
struct ulp_so_info *
parse_so_json(const char *path)
{
  int ret;

  json_object *root = json_object_from_file(path);
  assert(root && "Unable to build root object.");

  json_object *library = json_object_object_get(root, "library");
  if (!library) {
    WARN("%s is not valid: no library node.", path);
    return NULL;
  }

  json_object *name = json_object_object_get(library, "name");
  if (!name) {
    WARN("%s is not valid: no name.", path);
    return NULL;
  }

  json_object *buildid = json_object_object_get(library, "buildid");
  if (!buildid) {
    WARN("%s is not valid: no buildid.", path);
    return NULL;
  }

  struct ulp_so_info *so_info = calloc(1, sizeof(struct ulp_so_info));
  assert(so_info && "Error calling calloc.");

  so_info->name = strdup(json_object_get_string(name));

  ret = str_to_buildid(so_info->buildid, json_object_get_string(buildid));
  if (ret) {
    WARN("%s is not valid: invalid buildid.", path);
    release_so_info(so_info);
    return NULL;
  }

  /* Parse the symbols array.  */
  json_object *jsymbols = json_object_object_get(library, "symbols");
  struct symbol *symbols = parse_symbols_json(jsymbols);
  so_info->symbols = symbols;

  /* Release stuff.  */
  json_object_put(root);

  return so_info;
}

/** @brief Load the relevant so data from either JSON or ELF files.
 *
 * This function will open and parse the relevant informations from the target
 * library either in its original ELF file or the parsed JSON file.
 *
 * @param path          Path to file.
 *
 * @return              The ulp_so_info structure, or NULL in case of error.
 */
struct ulp_so_info *
ulp_so_info_open(const char *path)
{
  /* Check if path points to an ELF file and decide what to do.  */
  FILE *f = fopen(path, "rb");

  if (!f) {
    return NULL;
  }

  static const unsigned char elf_magic[] = { 127, 'E', 'L', 'F' };
  unsigned char elf_header[5];

  size_t n = fread(elf_header, 1, 5, f);
  fclose(f);

  if (n != 5) {
    return NULL;
  }

  if (memcmp(elf_magic, elf_header, ARRAY_LENGTH(elf_magic)) == 0) {
    return parse_so_elf(path);
  }
  else {
    return parse_so_json(path);
  }
}

/** @brief Release the `symbol` linked list object.
 *
 * Release all dynamic memory structures allocated when the symbol linked list
 * was created.
 *
 * @param symbol    Symbol to release.
 */
void
release_symbol(struct symbol *symbol)
{
  struct symbol *next;

  while (symbol) {
    FREE_AND_NULLIFY(symbol->name);
    next = symbol->next;
    FREE_AND_NULLIFY(symbol);
    symbol = next;
  }
}

/** @brief Release an `ulp_so_info` object.
 *
 * Release all dynamic memory structures allocated when the ulp_so_info object
 * was created.
 *
 * @param info    ulp_so_info to release.
 */
void
release_so_info(struct ulp_so_info *info)
{
  if (info) {
    FREE_AND_NULLIFY(info->name);
    release_symbol(info->symbols);
    FREE_AND_NULLIFY(info);
  }
}

/** @brief Get symbol with name  `sym`.
 *
 * This function transverses the `ulp_so_info` in order to find the symbol with
 * name that matches `sym` and returns it.]
 *
 * @param info     ulp_so_info to look for.
 * @param sym      Name of the symbol.
 *
 * @return         Symbol object with name = sym.
 */
struct symbol *
get_symbol_with_name(struct ulp_so_info *info, const char *sym)
{
  struct symbol *symbol = info->symbols;

  while (symbol) {
    if (!strcmp(symbol->name, sym)) {
      return symbol;
    }

    symbol = symbol->next;
  }

  return symbol;
}

int
run_extract(struct arguments *arguments)
{
  /* Path to input livepatch library target.  */
  const char *input_file = arguments->args[0];

  /* arguments->metadata is what is captured by the -o option.  */
  const char *output_file = arguments->metadata;

  /* In case the output is NULL then default to out.json.  */
  if (output_file == NULL)
    output_file = "out.json";

  struct ulp_so_info *info = parse_so_elf(input_file);
  FILE *out;

  if (!strcmp(output_file, "-"))
    out = stdout;
  else
    out = fopen(output_file, "w");

  /* Write the ulp_so_info structure as a JSON object.  */
  write_ulp_so_info_json(out, info);

  if (!strcmp(output_file, "-"))
    fclose(out);

  release_so_info(info);
  return 0;
}
