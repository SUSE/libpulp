/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017-2021 SUSE Software Solutions GmbH
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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <libgen.h>
#include <link.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <unistd.h>
#include <argp.h>

#include "arguments.h"
#include "config.h"
#include "error_common.h"
#include "insn_queue_tools.h"
#include "introspection.h"
#include "patches.h"
#include "terminal_colors.h"
#include "trigger.h"
#include "ulp_common.h"

static bool recursive_mode;
static bool disable_summarization;
static const char *prefix = NULL;
static bool disable_seccomp_p;

static bool
skippable_error(ulp_error_t err)
{
  return err == EBUILDID || err == ENOTARGETLIB || err == EUSRBLOCKED ||
         err == EWILDNOMATCH || err == EAPPLIED || err == ENOPATCH;
}

enum
{
  PROCESS_OTHER_ERROR = 0,
  PROCESS_PATCH_SUCCESS = 1 << 0,
  PROCESS_PATCH_SKIPPED = 1 << 1,
  PROCESS_PATCH_ERROR = 1 << 2,
};

/** @brief Apply a single live patch to one process.
 *
 *  This function does the dirty work of trigger: reverse and livepatching a
 *  process. It does so by checking if the given livepatch is suitable for
 *  the target process, and if so, proceeds hijacking all threads there
 *  to revert/apply patches.
 *
 *  @param target    ulp_process object of target process.
 *  @param retries   The number of retries to livepatch before giving up.
 *  @param livepatch The path to the metadata file (.ulp). Not necessary on
 *                   --revert-all unless atomic reverse & patch is desired.
 *  @param revert_library The library's basename which all livepatches will
 *                        be reversed.
 *
 *  @return 0 on success, anything else on error.
 */
static int
trigger_one_process(struct ulp_process *target, int retries,
                    const char *container_path, const char *revert_library,
                    bool check_stack, bool revert)
{
  char *livepatch = NULL;
  size_t livepatch_size = 0;
  int result;
  int ret;

  struct trigger_results *entry = NULL;

  /* Check if instruction queue in target process is compatible with current
     version of `ulp` tool.  */
  if (insnq_check_compatibility(target) == false) {
    ret = EOLDULP;
    goto metadata_clean;
  }

  /* Adjust the prefix to support processes that chrooted into /proc.  */
  const char *final_prefix;
  if (container_path || livepatch)
    final_prefix = adjust_prefix_for_chroot(target, prefix);

  /* Extract the livepatch metadata from .so file.  */
  if (container_path) {
    livepatch_size = extract_ulp_from_so_to_mem(container_path, revert,
                                                &livepatch, final_prefix);
    if (livepatch == NULL || livepatch_size == 0) {
      ret = ENOMETA;
      goto metadata_clean;
    }
  }

  if (livepatch) {
    ret = load_patch_info_from_mem(livepatch, livepatch_size);
    if (ret) {
      WARN("error parsing the metadata file (%s).", livepatch);
      goto metadata_clean;
    }
  }

  if (livepatch) {
    ret = check_patch_sanity(target, final_prefix);
    if (ret) {
      /* Sanity may fail because the patch should not be applied to this
         process.  */
      goto metadata_clean;
    }
  }

  /*
   * Since live patching uses AS-Unsafe functions from the context of a
   * signal-handler, libpulp first checks whether the operation could
   * lead to a deadlock and returns with EAGAIN if so. Detaching and
   * briefly waiting usually changes the situation and the assessment,
   * so retry in a finite loop.
   */
  result = -1;
  int retry = retries;
  while (retry) {
    retry--;

    ret = hijack_threads(target);
    if (ret == ETHRDDETTACH) {
      FATAL("fatal error during live patch application (hijacking).");
      goto metadata_clean;
    }
    if (ret > 0) {
      WARN("unable to hijack process.");
      goto metadata_clean;
    }

    if (check_stack) {
#if defined ENABLE_STACK_CHECK && ENABLE_STACK_CHECK
      ret = coarse_library_range_check(target, NULL);
      if (ret) {
        DEBUG("range check failed");
        goto range_check_failed;
      }
#endif
    }
    bool skip_patch_apply = false;
    if (revert_library) {
      result = revert_patches_from_lib(target, revert_library);
      if (result == -1) {
        FATAL("fatal error reverting livepatches (hijacked execution).");
        retry = 0;
      }
      /* In case we received a `No Target Lib` or `No patches reverted` error,
         ignore it because we are doing atomic patching and it may be the
         first patch we are trying to apply.  */
      if (livepatch && (result == ENOTARGETLIB || result == ENOPATCH)) {
        result = 0;
      }

      if (result) {
        DEBUG("live patching revert %d failed (attempt #%d).", target->pid,
              (retries - retry));
        skip_patch_apply = true;
      }
      else {
        retry = 0;
      }
    }

    if (livepatch && !skip_patch_apply) {
      result = apply_patch(target, livepatch, livepatch_size, disable_seccomp_p);
      if (result == -1) {
        FATAL(
            "fatal error during live patch application (hijacked execution).");
        retry = 0;
      }
      if (result)
        DEBUG("live patching %d failed (attempt #%d).", target->pid,
              (retries - retry));
      else
        retry = 0;
    }
#if defined ENABLE_STACK_CHECK && ENABLE_STACK_CHECK
  range_check_failed:
#endif

    ret = restore_threads(target);
    if (ret) {
      FATAL("fatal error during live patch application (restoring).");
      retry = 0;
    }
    if (result)
      usleep(1000);
  }

  if (result) {
    DEBUG("live patching failed.");
    ret = result;
    goto metadata_clean;
  }

  DEBUG("live patching succeeded.");
  ret = 0;

metadata_clean:
  /* Annotate error code and patch name.  */
  entry = calloc(1, sizeof(struct trigger_results));
  entry->next = target->results;
  if (container_path) {
    entry->patch_name = strdup(container_path);
  }
  else {
    char buf[128];
    snprintf(buf, 128, "reverted all patches from '%s'", revert_library);
    entry->patch_name = strdup(buf);
  }
  entry->err = ret;
  target->results = entry;

  release_ulp_global_metadata();
  if (livepatch) {
    free(livepatch);
  }
  return ret;
}

/** @brief Apply multiple live patches to one process.
 *
 *  This function reads all metadata files in `ulp_folder_path` and applies
 *  them to a process with pid = `pid`.
 *
 *  @param p               ulp_process object reference.
 *  @param retries         The number of retries to livepatch before giving up.
 *  @param ulp_folder_path The path to the folder containing all metadata
 * files.
 *  @param revert_library  The library's basename which all livepatches will
 *                         be reversed.
 *
 *  @return 0 on success, anything else on error.
 */
static int
trigger_many_ulps(struct ulp_process *p, int retries,
                  const char *wildcard_path, const char *library,
                  bool check_stack, bool revert)
{
  const char *wildcard = get_basename(wildcard_path);
  char *wildcard_path_dup = strdup(wildcard_path);
  char *ulp_folder_path = dirname(wildcard_path_dup);
  DIR *directory = opendir(ulp_folder_path);
  struct dirent *entry;
  char buffer[ULP_PATH_LEN];

  int ret = PROCESS_OTHER_ERROR, r = 0;
  int ulp_folder_path_len = strlen(ulp_folder_path);

  int wildcard_len = wildcard ? strlen(wildcard) : 0;

  if (!directory) {
    FATAL("Unable to open directory: %s", ulp_folder_path);
    ret = PROCESS_OTHER_ERROR;
    goto wildcard_clean;
  }

  strcpy(buffer, ulp_folder_path);
  strcat(buffer, "/");
  ulp_folder_path_len += 1;

  /* Iterate on each file of directory.  */
  while ((entry = readdir(directory)) != NULL) {
    int bytes;

    bytes = ulp_folder_path_len + strlen(entry->d_name);

    if (bytes >= ULP_PATH_LEN) {
      WARN("Path to %s is larger than %d bytes. Skipping...\n", entry->d_name,
           ULP_PATH_LEN);
      continue;
    }

    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      /* Skip the current and previous directory to avoid infinite loop.  */
      continue;
    }

    strcpy(buffer + ulp_folder_path_len, entry->d_name);

    if (is_directory(buffer)) {
      if (recursive_mode) {
        if (bytes + wildcard_len + 1 >= ULP_PATH_LEN) {
          WARN("Skipping %s: buffer overrun\n", entry->d_name);
          continue;
        }

        if (buffer[bytes - 1] != '/') {
          buffer[bytes++] = '/';
          buffer[bytes] = '\0';
        }

        if (wildcard) {
          /* Concatenate the wildcard.  */
          strcpy(buffer + bytes, wildcard);
        }

        r = trigger_many_ulps(p, retries, buffer, library, check_stack,
                              revert);
      }
      else {
        /* Skip directories.  */
        continue;
      }
    }

    const char *extension = strrchr(entry->d_name, '.');
    if (!extension) {
      /* File with no extension, skip.  */
      continue;
    }

    if (strcmp(extension, ".so") != 0) {
      /* This is not an .so file, skip.  */
      continue;
    }

    if (fnmatch(wildcard, entry->d_name, FNM_NOESCAPE) != 0) {
      /* Skip if file does not match wildcard.  */
      continue;
    }

    r = trigger_one_process(p, retries, buffer, library, check_stack, revert);
    if (r == 0) {
      ret |= PROCESS_PATCH_SUCCESS;
    }
    else if (skippable_error(r)) {
      ret |= PROCESS_PATCH_SKIPPED;
    }
    else {
      ret |= PROCESS_PATCH_ERROR;
    }
  }

  closedir(directory);

wildcard_clean:
  free(wildcard_path_dup);
  return ret;
}

static void
print_patched_unpatched(struct ulp_process *p, bool summarize)
{
  struct ulp_process *curr_item = p;

  pid_t pid = curr_item->pid;
  struct trigger_results *results, *summarized_result = NULL;

  /* Try to summarize the patches result.  */
  ulp_error_t err = EUNKNOWN;
  bool summarized = true;
  bool hide_skipped = false;

  if (curr_item->results)
    err = curr_item->results->err;

  for (results = curr_item->results; results; results = results->next) {
    if (results->err == 0 ||
        (results->err != EBUILDID && results->err != ENOTARGETLIB)) {
      /* Patch applied or critical error found.  Hide minor 'skipped' errors
         and try to summarize this error.  */
      err = results->err;
      hide_skipped = true;
    }
  }

  for (results = curr_item->results; results; results = results->next) {
    /* if marked to hide sipped patches, then proceed to next one.  */
    if (hide_skipped &&
        (results->err == EBUILDID || results->err == ENOTARGETLIB))
      continue;

    if (results->err != err) {
      /* There are multiple events  and we are unable to summarize.  */
      summarized = false;
    }
    else if (results->err != EBUILDID && results->err != ENOTARGETLIB) {
      if (!summarized_result) {
        /* So far, only one important event was catch.  */
        summarized_result = results;
      }
      else {
        /* Multiple important events happened.  Unable to summarize.  */
        summarized = false;
      }
    }
  }

  /* If the patched list is empty, it means that no patch was even tried to be
     applied, perhaps because no files matched the wildcard.  */
  if (summarized_result == NULL && summarized == true) {
    return;
  }

  if (!summarize) {
    summarized = false;
    hide_skipped = false;
  }

  printf("  %s (pid: %d):", get_process_name(curr_item), pid);
  if (summarized) {
    if (skippable_error(err)) {
      change_color(TERM_COLOR_YELLOW);
      printf(" SKIPPED");
      change_color(TERM_COLOR_RESET);
      printf(" %s\n", libpulp_strerror(err));
    }
    else if (err) {
      change_color(TERM_COLOR_RED);
      printf(" FAILED");
      change_color(TERM_COLOR_RESET);
      if (summarized_result)
        printf(" %s: %s\n", summarized_result->patch_name,
               libpulp_strerror(err));
    }
    else {
      change_color(TERM_COLOR_GREEN);
      printf(" SUCCESS");
      change_color(TERM_COLOR_RESET);
      if (summarized_result)
        printf(" %s\n", summarized_result->patch_name);
    }
  }
  else {
    putchar('\n');
    for (results = curr_item->results; results; results = results->next) {
      if (results->err == EBUILDID || results->err == ENOTARGETLIB) {
        if (!hide_skipped) {
          change_color(TERM_COLOR_YELLOW);
          printf("    SKIPPED");
          change_color(TERM_COLOR_RESET);
          printf(" %s: %s\n", results->patch_name,
                 libpulp_strerror(results->err));
        }
      }
      else if (results->err) {
        change_color(TERM_COLOR_RED);
        printf("    FAILED");
        change_color(TERM_COLOR_RESET);
        printf(" %s: %s\n", results->patch_name,
               libpulp_strerror(results->err));
      }
      else {
        change_color(TERM_COLOR_GREEN);
        printf("    SUCCESS");
        change_color(TERM_COLOR_RESET);
        printf(" %s\n", results->patch_name);
      }
    }
  }
}

/** @brief Apply multiple live patches to all processes with libpulp loaded.
 *
 *  This function reads all metadata files in `ulp_folder_path` and applies
 *  them to every process that haves libpulp loaded.
 *
 *  @param retries         The number of retries to livepatch before giving up.
 *  @param ulp_folder_path The path to the folder containing all metadata
 * files.
 *  @param revert_library  The library's basename which all livepatches will
 *                         be reversed.
 *
 *  @return 0 on success, anything else on error.
 */
static int
trigger_many_processes(const char *process_wildcard, int retries,
                       const char *ulp_folder_path, const char *library,
                       bool check_stack, bool revert)
{
  struct ulp_process *p;
  int ret = 0;
  int successes = 0;
  int skippes = 0;
  int failures = 0;

  bool is_wildcard = ulp_folder_path && strchr(ulp_folder_path, '*');

  /* Iterate over the process list that have libpulp preloaded.  */
  FOR_EACH_ULP_PROCESS_MATCHING_WILDCARD(p, process_wildcard)
  {
    int r;

    /* FIXME: trigger_many_ulps and trigger_one_process should not return
       very distinct error values.  */

    if (is_wildcard) {
      /* If a wildcard is provided, trigger all files that matches it.  */
      r = trigger_many_ulps(p, retries, ulp_folder_path, library, check_stack,
                            revert);

      /* In the case the process was patched, then do not count 'skipped'
       * patches as it is irrelevant.  */
      if (r & PROCESS_PATCH_SUCCESS) {
        successes++;
      }
      else if (r & PROCESS_PATCH_SKIPPED) {
        skippes++;
      }

      /* Count the processes that got an error even if one of the patches
       * successes.  */
      if (r & PROCESS_PATCH_ERROR) {
        failures++;
      }
    }
    else {
      /* This may simply be a file.  Patch it. */
      r = trigger_one_process(p, retries, ulp_folder_path, library,
                              check_stack, revert);

      /* If the livepatch failed because the patch wasn't targeted to the
         proccess, we ignore because we are batch processing.  */
      if (skippable_error(r)) {
        skippes++;
      }
      else {
        ret |= r;
        if (r == 0) {
          successes++;
        }
        else {
          failures++;
        }
      }
    }

    if (!ulp_quiet)
      print_patched_unpatched(p, !disable_summarization);
  }

  if (successes + skippes + failures > 0) {
    printf("ulp: Processes patched: %d, Skipped: %d, Failed: %d.\n", successes,
           skippes, failures);
  }

  return ret;
}

extern bool enable_threading;

/** @brief Check if the ulp tool can disable seccomp
 *
 * Disabling seccomp needs a special capability CAP_SYS_ADMIN which the
 * user may not have.  Hence we need to check if the user have this.
 *
 * @return true if capability is met, false otherwise.
*/
static bool check_sys_admin(void)
{
  bool ret = false;

  /* Index according to libcap.  */
  const int index = 21;

  /* Open the status file of `ulp` tool process.  */
  FILE *file = fopen("/proc/self/status", "r");

  /* Well, if we can't open the status file we surely are not priviledged.  */
  if (file == NULL) {
    return false;
  }

  ssize_t nread;
  size_t size;
  char *line = NULL;

  while ((nread = getline(&line, &size, file)) != -1) {
    char *token = strtok(line, " \t\n");
    if (strcmp(token, "CapPrm:") == 0) {
      /* Found field.  Lets parse it.  */
      char *value_str = strtok(NULL, " \t\n");
      uint64_t value;
      int reads = sscanf(value_str, "%lx", &value);

      if (reads != 1) {
        /* Error reading string.  */
        ret = false;
        goto sys_adm_clear;
      }

      /* Check if we got the capability we want.  */
      if ((value & (1 << index)) != 0) {
        ret = true;
      } else {
        ret = false;
      }

      /* Clean everything and return.  */
      goto sys_adm_clear;
    }
  }

sys_adm_clear:
  FREE_AND_NULLIFY(line);
  fclose(file);
  return ret;
}

/** @brief Trigger command entry point.
 */
int
run_trigger(struct arguments *arguments)
{
  /* Set the verbosity level in the common introspection infrastructure. */
  ulp_verbose = arguments->verbose;
  ulp_quiet = arguments->quiet;
  enable_threading = !arguments->disable_threads;
  recursive_mode = arguments->recursive;
  disable_summarization = arguments->no_summarization;
  disable_seccomp_p = arguments->disable_seccomp;

  bool check_stack = false;
  const char *library = arguments->library;
  const char *ulp_folder_path = arguments->args[0];
  int retry = arguments->retries;
  const char *process_wildcard = arguments->process_wildcard;
  bool revert = (arguments->revert > 0);
  int ret;

  if (arguments->user_wildcard) {
    WARN("error: user wildcard is currently unsupported in trigger");
    return ENOSYS;
  }

  if (disable_seccomp_p && !check_sys_admin()) {
    WARN("error: disabling seccomp requires CAP_SYS_ADMIN, but user does not provide it.\n"
         "suggestion: run ulp as root.");
    return EPERM;
  }

  /* Set global static prefix variable.  */
  prefix = arguments->prefix;

#if defined ENABLE_STACK_CHECK && ENABLE_STACK_CHECK
  check_stack = arguments->check_stack;
#endif
  ret = trigger_many_processes(process_wildcard, retry, ulp_folder_path,
                               library, check_stack, revert);

  return ret;
}

struct argp_option *
get_command_option_trigger(void)
{
  static struct argp_option options[] = {
    { 0, 0, 0, 0, "Options:", 0 },
    { "verbose", 'v', 0, 0, "Produce verbose output", 0 },
    { "quiet", 'q', 0, 0, "Don't produce any output", 0 },
    { "process", 'p', "process", 0, "Target process name, wildcard, or PID", 0 },
    { "user", 'u', "user", 0, "User name, wildcard, or UID", 0 },
    { "disable-threading", ULP_OP_DISABLE_THREADING, 0, 0,
      "Do not launch additional threads", 0 },
    { "revert-all", ULP_OP_REVERT_ALL, "LIB", 0,
      "Revert all patches from LIB. If LIB=target, then all patches from the "
      "target library within the passed livepatch will be reverted.",
      0 },
    { "timeout", ULP_OP_TIMEOUT, "t", 0,
      "Set trigger timeout to t seconds (default 200s)", 0 },
    { "disable-summarization", ULP_OP_DISABLE_SUMMARIZATION, 0, 0,
      "Disable trigger ouput summarization", 0 },
    { "recursive", ULP_OP_RECURSIVE, 0, 0, "Search for patches recursively", 0 },
    { "root", 'R', "PREFIX", 0,
      "Append prefix to livepatch path when passing it to target process", 0 },
    { "disable-seccomp", ULP_OP_DISABLE_SECCOMP, 0, 0,
      "disable seccomp filters on target process (use for testing purposes)", 0 },
  #if defined ENABLE_STACK_CHECK && ENABLE_STACK_CHECK
    { "check-stack", 'c', 0, 0, "Check the call stack before live patching", 0 },
  #endif
    { "retries", 'r', "N", 0, "Retry N times if process busy", 0 },
    { "revert", ULP_OP_REVERT, 0, 0,
      "revert livepatch.", 0 },
    { "color", ULP_OP_COLOR, "yes/no/auto", 0, "Enable/disable colored messages", 0 },
    { 0 }
  };

  return options;
}
