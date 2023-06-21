/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2020-2021 SUSE Software Solutions GmbH
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

#include <argp.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <libelf.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <unistd.h>

#include "arguments.h"
#include "config.h"
#include "elf-extra.h"
#include "error_common.h"
#include "introspection.h"
#include "patches.h"
#include "pcqueue.h"
#include "terminal_colors.h"

bool enable_threading = false;
static bool original_enable_threading;

void insert_target_process(int pid, struct ulp_process **list);

static void *
generate_ulp_list_thread(void *args)
{
  struct ulp_process_iterator *it = args;

  pid_t pid;
  const char *wildcard = it->wildcard;
  const char *usr_wildcard = it->user_wildcard;
  uid_t target_uid = it->target_uid;

  while ((it->subdir = readdir(it->slashproc))) {
    /* Skip non-numeric directories in /proc. */
    if (!isnumber(it->subdir->d_name))
      continue;

    pid = atoi(it->subdir->d_name);

    /* Optimization: If no wildcard is provided, do not bother geting target
       name because it doesn't matter.  */
    if (wildcard) {
      const char *process_name = get_target_binary_name(pid);
      /* Skip processes that does not match the wildcard. */
      if (wildcard != NULL && process_name != NULL &&
          fnmatch(wildcard, process_name, 0) != 0)
        continue;
    }

    if (usr_wildcard) {
      uid_t uid = get_process_owner(pid);
      if (target_uid > 0) {
        if (uid != target_uid)
          continue;
      }
      else if (uid > 0) {
        struct passwd *pw = getpwuid(uid);
        const char *usr_name = pw ? pw->pw_name : NULL;

        /* Skip processes which does not match user name wildcard.  */
        if (usr_name && fnmatch(usr_wildcard, usr_name, 0) != 0) {
          continue;
        }
      }
    }

    /* If process is the ULP tool itself, skip it.  We cannot livepatch the
       tool itself.  Gödel and Cantor would not be proud...  */
    if (pid == getpid())
      continue;

    /* Add live patchable process. */
    if (has_libpulp_loaded(pid)) {
      insert_target_process(pid, &it->last);
      if (enable_threading)
        producer_consumer_enqueue(it->pcqueue, it->last);
      else
        return it->last;
    }
  }

  closedir(it->slashproc);
  if (enable_threading)
    producer_consumer_enqueue(it->pcqueue, NULL);
  return NULL;
}

struct ulp_process *
process_list_next(struct ulp_process_iterator *it)
{
  if (!it->slashproc)
    return (it->now = NULL);

  if (enable_threading) {
    it->now = producer_consumer_dequeue(it->pcqueue);
  }
  else {
    it->now = generate_ulp_list_thread(it);
  }
  return it->now;
}

/** Thread object that runs generating the process list and parsing the libpulp
    symbols.  */
static pthread_t process_list_thread;

struct ulp_process *
process_list_begin(struct ulp_process_iterator *it,
                   const char *procname_wildcard, const char *user_wildcard)
{
  memset(it, 0, sizeof(*it));

  pid_t pid;
  it->wildcard = procname_wildcard;
  it->user_wildcard = user_wildcard;
  it->target_uid = 0;

  original_enable_threading = enable_threading;

  if (isnumber(procname_wildcard)) {
    /* If wildcard is actually a number, then treat it as a PID.  */
    pid = atoi(procname_wildcard);
    insert_target_process(pid, &it->last);
    it->now = it->last;

    /* Disable threading in this case.  */
    enable_threading = false;
    return it->now;
  }

  /* In case the user wildcard is a number, then treat it as a uid.  */
  if (isnumber(user_wildcard)) {
    it->target_uid = strtol(user_wildcard, NULL, 10);
  }

  /* Build a list of all processes that have libpulp.so loaded. */
  it->slashproc = opendir("/proc");
  if (it->slashproc == NULL) {
    perror("Is /proc mounted?");
    return NULL;
  }

  if (enable_threading) {
    it->pcqueue = producer_consumer_new(512);
    pthread_create(&process_list_thread, NULL, generate_ulp_list_thread, it);
  }

  return process_list_next(it);
}

int
process_list_end(struct ulp_process_iterator *it)
{
  if (it->now == NULL) {
    release_ulp_process(it->last);
    producer_consumer_delete(it->pcqueue);
    if (enable_threading) {
      pthread_join(process_list_thread, NULL);
    }

    /* In case threads were disabled because of some special case, then enable
       it now.  */
    enable_threading = original_enable_threading;
    return 0;
  }

  return 1;
}

/* Returns 0 if libpulp.so has been loaded by the process with memory map
 * (/proc/<pid>/maps) opened in MAP. Otherwise, returns 1.
 */
int
libpulp_loaded(FILE *map)
{
  int retcode = 0;

  char *line = NULL;
  size_t len = 0;

  /* Read all lines of MAP and look for the 'libpulp.so' substring. */
  rewind(map);
  while (getline(&line, &len, map) != -1) {
    if (strstr(line, "libpulp.so")) {
      retcode = 1;
      break;
    }
  }

  /* Free structures allocated by getline() and return. */
  free(line);
  return retcode;
}

/** @brief Extract .ulp.comment section from livepatch container .so
 *
 * Extract the content of the .ulp.comment section within the livepatch
 * container .so file into a buffer passed by reference through `out`, and
 * returns the size of it. If the section does not exists, then 0 is returned
 * and out is set to NULL;
 *
 * @param livepatch  Path to livepatch container (.so)
 * @param out        Buffer containing the .ulp.comment section, passed by
 *                   reference.
 *
 * @return Size of the section content.
 * */
size_t
extract_ulp_comment_to_mem(const char *livepatch, char **out)
{
  int fd;
  const char *section = ".ulp.comments";

  Elf *elf = load_elf(livepatch, &fd);
  if (elf == NULL) {
    *out = NULL;
    return 0;
  }

  Elf_Scn *ulp_scn = get_elfscn_by_name(elf, section);
  if (ulp_scn == NULL) {
    unload_elf(&elf, &fd);
    *out = NULL;
    return 0;
  }

  Elf_Data *ulp_data = elf_getdata(ulp_scn, NULL);
  if (ulp_data->d_buf == NULL || ulp_data->d_size == 0) {
    unload_elf(&elf, &fd);
    *out = NULL;
    return 0;
  }

  /* Create buffer large enough to hold the final metadata.  */
  uint32_t meta_size = ulp_data->d_size;
  char *final_meta = (char *)malloc(meta_size);

  memcpy(final_meta, ulp_data->d_buf, ulp_data->d_size);

  unload_elf(&elf, &fd);
  *out = final_meta;
  return meta_size;
}

/** @brief Print only relevant labels in the comment section.
 *
 * The comment section may have references to bugs or cve codes. Those are
 * important codes and should be displayed on the patch listing. This function
 * will search for and print each of them so the user can be informed about
 * the vulnerabilities
 *
 * @param lib_path   Path to library.
 *
 * @return Size of the section content.
 **/
static void
print_relevant_labels(const char *lib_path)
{
  char *buf;

  char *head;
  bool printed_header = false;

  extract_ulp_comment_to_mem(lib_path, &buf);

  if (buf == NULL)
    return;

  head = buf;

  while (*head != '\0') {
    char *str = NULL;
    if (!strncasecmp(head, "bsc#", 4)) {
      /* bsc#<number>*.  */
      str = head;
      head += 4;

      while (*head != '\0' && isdigit(*head))
        head++;

      if (*head != '\0') {
        *head = '\0';
      }
    }
    else if (!strncasecmp(head, "jsc#", 4)) {
      /* bsc#<alpha>*-<number>*.  */

      str = head;
      head += 4;

      while (*head != '\0' && isalpha(*head) && *head != '-')
        head++;

      if (*head == '-') {
        head++;
        while (*head != '\0' && isdigit(*head))
          head++;
      }

      if (*head != '\0') {
        *head = '\0';
      }
    }
    else if (!strncasecmp(head, "cve-", 4)) {
      /* cve-<number>*-<number>*.  */
      str = head;
      head += 4;

      while (*head != '\0' && *head != '-' && isdigit(*head))
        head++;

      if (*head == '-') {
        head++;
        while (*head != '\0' && isdigit(*head))
          head++;
      }

      if (*head != '\0') {
        *head = '\0';
      }
    }

    if (str) {
      if (printed_header == false) {
        printed_header = true;
        printf("        bug labels: ");
      }
      printf("%s ", str);
    }

    head++;
  }

  if (printed_header) {
    putchar('\n');
  }

  free(buf);
}

/** @brief Print all livepatches applied to library.
 *
 * @param patch   Patch object.
 * @param libname Base name of library.
 */
void
print_lib_patches(struct ulp_applied_patch *patch, const char *libname)
{
  /* Ensure that the basename was passed.  */
  libname = get_basename(libname);

  while (patch) {
    if (!strcmp(libname, patch->lib_name)) {
      printf("      livepatch: %s\n", get_basename(patch->container_name));
      print_relevant_labels(patch->container_name);
    }
    patch = patch->next;
  }
}

/** @brief Check if function at `sym_address` has the NOP preamble.
 *
 * Functions that are livepatchable has ULP_NOPS_LEN - PRE_NOPS_LEN at the
 * beginning of the function. Check the existence of this preamble.
 *
 * @param sym_address  Address of function in target process.
 * @param pid          Pid of the target process.
 *
 * @return  True if preamble exists, false if not.
 */
static bool
check_preamble(ElfW(Addr) sym_address, pid_t pid)
{
  unsigned char bytes[2];

  if (read_memory((char *)bytes, 2, pid, sym_address)) {
    /* In case it was unable to read the symbol due to permission error, just
     * warn in debug output.  */
    DEBUG("Unable to read symbol preamble at address %lx in process %d",
          sym_address, pid);
    return false;
  }

  /* Check for NOP NOP or XGCH AX, AX.  */
  if ((bytes[0] == 0x90 || bytes[0] == 0x66) && bytes[1] == 0x90)
    return true;
  return false;
}

/** @brief Check if `libname` has a livepatch loaded.
 *
 * Check if the library with name `libname` has a livepatch loaded in the
 * `patch` chain.
 *
 * @param patch   List of loaded patches in the target process.
 * @param libname Name of the library in target process.
 *
 * @return true if libname has a livepatch loaded. False elsewhere.
 *
 */
static bool
has_livepatch_loaded(struct ulp_applied_patch *patch, const char *libname)
{
  if (libname == NULL)
    return false;

  /* Ensure that the basename was passed.  */
  libname = get_basename(libname);

  while (patch) {
    if (!strcmp(libname, patch->lib_name)) {
      return true;
    }
    patch = patch->next;
  }

  return false;
}

/** @brief Check if library in `obj` on target process is livepatchable.
 *
 * Check on the target process with `pid` if the library on `obj` is
 * livepatchable. The `patch` object with the target process loaded
 * livepatches is necessary because the following:
 *
 * A library is livepatchable if their functions has the ULP NOP preamble.
 * However, if the preamble does not exists, then:
 * 1. The library was already livepatched, and thus is livepatchable.
 * 2. The library is not livepatchable.
 *
 * @param patch  The list of patches loaded in the target process.
 * @param obj    The libary object.
 * @param pid    Pid of target process.
 *
 * @return       True if livepatchable, False if not.
 */
static bool
is_library_livepatchable(struct ulp_applied_patch *patch,
                         struct ulp_dynobj *obj, pid_t pid)
{
  int i, ret;
  if (has_livepatch_loaded(patch, obj->filename))
    return true;

  if (attach(pid)) {
    DEBUG("Unable to attach to %d to read data.\n", pid);
    ret = false;
    goto detach_process;
  }

  ElfW(Addr) ehdr_addr = obj->link_map.l_addr;
  ElfW(Addr) dynsym_addr = obj->dynsym_addr;

  if (ehdr_addr == 0) {
    /* If l_addr is zero, it means that there is no load bias.  In that case,
     * the elf address is on address 0x400000 on x86_64.  */
    ehdr_addr = 0x400000UL;
  }

  /* FIXME: Some applications take a very long time to decide if library is
     livepatchable because the library has a lot of symbols.  In this case we
     limit the number of symbols to read to a constant value.  Statistics shows
     that 8000 is a reasonable number (see issue #159).  */
  int len = MIN(obj->num_symbols, 8000);

  for (i = 0; i < len; i++) {
    ElfW(Sym) sym;

    ret = read_memory((char *)&sym, sizeof(sym), pid, dynsym_addr);
    if (ret) {
      WARN("Unable to read dynamic symbol");
      ret = false;
      goto detach_process;
    }

    ElfW(Addr) sym_addr = ehdr_addr + sym.st_value;

    if (check_preamble(sym_addr, pid)) {
      ret = true;
      goto detach_process;
    }

    dynsym_addr += sizeof(sym);
  }

detach_process:
  if (detach(pid)) {
    DEBUG("Unable to detach %d.\n", pid);
    return false;
  }

  return (bool)ret;
}

void
print_remote_err_status(struct ulp_process *p)
{
  ulp_error_t state = get_libpulp_error_state_remote(p);

  printf("  Livepatching status: ");
  switch (state) {
    case ENONE:
    case EOLDLIBPULP:
      /* Report enabled for old libpulp.  */
      change_color(TERM_COLOR_GREEN);
      printf("enabled\n");
      break;

    case EUSRBLOCKED:
      change_color(TERM_COLOR_YELLOW);
      printf("disabled by user\n");
      break;

    default:
      change_color(TERM_COLOR_RED);
      printf("disabled (internal error: %s)\n", libpulp_strerror(state));
      break;
  }

  change_color(TERM_COLOR_RESET);
}

void
print_process(struct ulp_process *process, int print_buildid)
{
  struct ulp_dynobj *object_item;
  pid_t pid = process->pid;
  struct ulp_applied_patch *patch = ulp_read_state(process);
  printf("PID: %d, name: %s\n", pid, get_process_name(process));
  print_remote_err_status(process);
  printf("  Livepatchable libraries:\n");
  object_item = dynobj_first(process);
  if (!object_item)
    printf("    (none)\n");
  while (object_item) {
    if (is_library_livepatchable(patch, object_item, pid)) {
      printf("    in %s", object_item->filename);
      if (print_buildid)
        printf(" (%s)", buildid_to_string(object_item->build_id));
      printf(":\n");

      print_lib_patches(patch, object_item->filename);
    }

    object_item = dynobj_next(process, object_item);
  }
  release_ulp_applied_patch(patch);
  printf("\n");
}

bool
has_libpulp_loaded(pid_t pid)
{
  bool ret = false;
  char mapname[PATH_MAX];
  FILE *map;

  snprintf(mapname, PATH_MAX, "/proc/%d/maps", pid);
  if ((map = fopen(mapname, "r")) == NULL) {
    /* EACESS error happens when the tool is executed by a regular user.
       This is not a hard error.
       ENOENT happens when the process finished in between this process.  */
    if (errno != EACCES && errno != ENOENT)
      perror("Unable to open memory map for process");
    return false;
  }

  /* If the process identified by PID is live patchable, add to LIST. */
  if (libpulp_loaded(map)) {
    ret = true;
  }

  fclose(map);
  return ret;
}

/* Inserts a new process structure into LIST if the process identified
 * by PID is live-patchable.
 */
void
insert_target_process(int pid, struct ulp_process **list)
{
  struct ulp_process *new = NULL;
  int ret;

  new = calloc(1, sizeof(struct ulp_process));

  new->pid = pid;
  ret = initialize_data_structures(new);
  if (ret) {
    WARN("error gathering target process information.");
    release_ulp_process(new);
    return;
  }
  else {
    new->next = *list;
    *list = new;
  }
}

/** @brief Prints all the info collected about the processes in `process_list`.
 *
 * @param process_list List of processes.
 * @param print_buildid Print build id identifier of library.
 */
void
print_process_list(struct ulp_process *process_list, int print_buildid)
{
  struct ulp_process *process_item;

  process_item = process_list;
  while (process_item) {
    print_process(process_item, print_buildid);
    process_item = process_item->next;
  }
}

int
run_patches(struct arguments *arguments)
{
  bool print_build_id = arguments->buildid;
  ulp_quiet = arguments->quiet;
  ulp_verbose = arguments->verbose;
  enable_threading = !arguments->disable_threads;
  const char *process_wildcard = arguments->process_wildcard;
  const char *user_wildcard = arguments->user_wildcard;

  struct ulp_process *p;

  FOR_EACH_ULP_PROCESS_FROM_USER_WILDCARD(p, process_wildcard, user_wildcard)
  {
    print_process(p, print_build_id);
  }

  return 0;
}
