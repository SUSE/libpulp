/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017-2018 SUSE Linux GmbH
 *
 *  This file is part of libpulp.
 *
 *  libpulp is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  libpulp is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with libpulp.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  Author: Joao Moreira <jmoreira@suse.de>
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <link.h>
#include <dirent.h>
#include <bfd.h>
#include <stddef.h>
#include <fcntl.h>
#include <sys/user.h>

#include "ptrace.h"
#include "introspection.h"
#include "../../include/ulp_common.h"

ulp_process target;
ulp_addresses addr;
struct ulp_metadata ulp;

int check_args(int argc, char *argv[])
{
    if (argc != 3)
    {
	WARN("Usage: %s <pid> <livepatch path>", argv[0]);
	return 1;
    }

    if (strlen(argv[2]) > ULP_PATH_LEN)
    {
	WARN("livepatch path is limited to %d bytes.", ULP_PATH_LEN);
	return 2;
    }

    return 0;
}

int patch_applied()
{
    struct ulp_thread *t;
    struct user_regs_struct context;
    int patched;

    t = target.threads;
    if (set_id_buffer(ulp.patch_id, t)) return 2;

    /* redirect control-flow to trigger */
    context = t->context;
    context.rip = addr.check + 2;

    if (run_and_redirect(t->tid, &context, addr.loop))
    {
	WARN("error: unable to trig thread %d.", t->tid);
	return 1;
    };

    /* capture trigger return */
    patched = context.rax;
    //context = t->context;

    /*
    if (attach(t->tid))
    {
	WARN("apply patch error (attach).");
	return 2;
    }

    / put thread back into loop /
    if (set_regs(t->tid, &context))
    {
	WARN("apply patch error (set_regs).");
	return 3;
    };

    if (detach(t->tid))
    {
	WARN("apply patch error (detach).");
	return 4;
    }*/

    /*if (!patched)
    {
	WARN("apply patch error: patch not applied.");
	return 5;
    }*/

    return patched;
}




int main(int argc, char **argv)
{
    int pid;
    int var;
    int consistent;
    char *livepatch;
    int patched = -1;

    if (check_args(argc, argv)) return 2;
    pid = atoi(argv[1]);
    livepatch = argv[2];

    if (stop(pid)) return 3;
    if (initialize_data_structures(pid, livepatch)) return 4;

    /* verify if to-be-patched libs support libpulp */
    if (check_patch_sanity(livepatch)) return 5;

    if (hijack_threads()) return 6;

    if (restart(pid)) return 7;

    if (patch_applied(livepatch))
    {
        WARN("Process %d was already patched.", pid);
        patched = 1;
    } else {
        WARN("Process %d not patched.", pid);
        patched = 0;
    }

    if (stop(pid)) return 8;

    if (restore_threads()) return 9;

    if (restart(pid)) return 10;

    return patched;
}
