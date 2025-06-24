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

#include "set_patchable.h"
#include "arguments.h"
#include "introspection.h"
#include "patches.h"
#include "ulp_common.h"

#include <stddef.h>
#include <unistd.h>
#include <argp.h>

/** Enable or disable threading in process discovery.  */
extern bool enable_threading;

/** Run the __ulp_enable_disable_livepatching in libpulp.  */
static int
run_enable_disable_patching(struct ulp_process *p)
{
  struct ulp_thread *thread = p->main_thread;
  registers_t context = thread->context;
  Elf64_Addr routine = p->dynobj_libpulp->enable_disable_patching;

  int ret = run_and_redirect(thread->tid, &context, routine);

  if (ret) {
    return ret;
  }

  return FUNCTION_RETURN_REG(context);
}

/** @brief Enable or disable livepatching on remote process.
 *
 * Given a remote process `p`, this function will enable or disable the
 * livepatch capabilites of `p` according to `enable` variable.
 *
 * @param p        Process to enable/disable livepatching.
 * @param enable   Enable or disable livepatching.
 * @param retries  How many attempts if the process is busy?
 *
 * @return         ENONE if success, anything else if error.
 **/
static ulp_error_t
enable_or_disable_patching(struct ulp_process *p, bool enable, int retries)
{
  ulp_error_t state = get_libpulp_error_state_remote(p);
  int ret;

  if ((state == ENONE && enable == false) ||
      (state == EUSRBLOCKED && enable == true)) {

    for (int i = 0; i < retries; i++) {
      if (hijack_threads(p)) {
        WARN("unable to hijack process with pid: %d.", p->pid);
        break;
      }

      ret = run_enable_disable_patching(p);

      if (restore_threads(p)) {
        WARN("unable to restore thread in process with pid: %d.", p->pid);
        break;
      }

      if (ret != EAGAIN) {
        break;
      }

      DEBUG("enabling/disabling libpulp failed: locks were busy.");
      usleep(1000);
    }

    /* ulp_enable_or_disable_patchig returns the new error state, so check if
       the returned state is what we expect to.  */
    if ((ret == ENONE && enable) || (ret == EUSRBLOCKED && !enable)) {
      WARN("Process %s (pid: %d): livepatching is now %s.",
           get_target_binary_name(p->pid), p->pid,
           enable ? "enabled" : "disabled");
    }
    else {
      WARN("Unable to change status of process %d: %s (libpulp in error "
           "state).",
           p->pid, libpulp_strerror(ret));
    }

    return ENONE;
  }

  /* Can not do that, as libpulp is in error state.  */
  return state;
}

int
run_set_patchable(struct arguments *arguments)
{
  ulp_quiet = arguments->quiet;
  ulp_verbose = arguments->verbose;
  enable_threading = !arguments->disable_threads;
  const char *process_wildcard = arguments->process_wildcard;
  const char *user_wildcard = arguments->user_wildcard;
  int retries = arguments->retries;
  bool enable;
  struct ulp_process *p;

  if (!strcasecmp(arguments->args[0], "enable")) {
    enable = true;
  }
  else if (!strcmp(arguments->args[0], "disable")) {
    enable = false;
  }
  else {
    WARN("Empty argument. Expected: 'enable' or 'disable'");
    return 1;
  }

  FOR_EACH_ULP_PROCESS_FROM_USER_WILDCARD(p, process_wildcard, user_wildcard)
  {
    enable_or_disable_patching(p, enable, retries);
  }

  return 0;
}

struct argp_option *
get_command_option_set_patchable(void)
{
  static struct argp_option options[] = {
    { 0, 0, 0, 0, "Options:", 0 },
    { "verbose", 'v', 0, 0, "Produce verbose output", 0 },
    { "quiet", 'q', 0, 0, "Don't produce any output", 0 },
    { "process", 'p', "process", 0, "Target process name, wildcard, or PID", 0 },
    { "user", 'u', "user", 0, "User name, wildcard, or UID", 0 },
    { "disable-threading", ULP_OP_DISABLE_THREADING, 0, 0,
    "Do not launch additional threads", 0 },
    { "retries", 'r', "N", 0, "Retry N times if process busy", 0 },
    { 0 }
  };

  return options;
}
