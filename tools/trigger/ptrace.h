/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017-2020 SUSE Software Solutions GmbH
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

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include "../../include/ulp_common.h"

/* Memory read/write helper functions */
int write_byte(char byte, int pid, Elf64_Addr addr);

int write_string(char *buffer, int pid, Elf64_Addr addr);

int read_byte(char *byte, int pid, Elf64_Addr addr);

int read_memory(char *byte, size_t len, int pid, Elf64_Addr addr);

int read_string(char **buffer, int pid, Elf64_Addr addr);

/* Signaling functions */
int stop(int pid);

int restart(int pid);

/* attach/detach and run functions */
int attach(int pid);

int detach(int pid);

int get_regs(int pid, struct user_regs_struct *regs);

int set_regs(int pid, struct user_regs_struct *regs);

int run_and_redirect(int pid, struct user_regs_struct *regs, Elf64_Addr addr);
