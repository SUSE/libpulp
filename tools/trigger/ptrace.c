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
#include <unistd.h>
#include "../../include/ulp_common.h"
#include "introspection.h"
#include "ptrace.h"

/* Memory read/write helper functions */
int write_byte(char byte, int pid, Elf64_Addr addr)
{
    Elf64_Addr value;

    if (attach(pid))
    {
	WARN("Unable to attach to %d.\n", pid);
	return 1;
    };

    value = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
    if (errno) {
	WARN("Unable to read byte (write).\n");
	return 2;
    }
    memset(&value, byte, 1);
    ptrace(PTRACE_POKEDATA, pid, addr, value);
    if (errno) {
	WARN("Unable to write byte.\n");
	return 3;
    }

    if (detach(pid))
    {
	WARN("Unable to detach from %d.\n", pid);
	return 4;
    };

    return 0;
}

int write_string(char *buffer, int pid, Elf64_Addr addr)
{
    int i;

    for (i = 0; i < 255 && buffer[i] != '\0'; i++) {
	if (write_byte(buffer[i], pid, addr + i)) return 2;
    }

    if (write_byte('\0', pid, addr + i)) return 3;

    return 0;
}

int read_byte(char *byte, int pid, Elf64_Addr addr)
{
    Elf64_Addr value;

    value = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
    if (errno)
    {
	return 1;
    }
    *byte = value & 0xff;

    return 0;
}

int read_memory(char *byte, size_t len, int pid, Elf64_Addr addr)
{
    size_t i;

    if (attach(pid))
    {
	WARN("Unable to attach to %d.\n", pid);
	return 1;
    };

    for (i = 0; i < len; i++) {
	if (read_byte(byte + i, pid, addr + i)) {
	    WARN("read_memory error.\n");
	    return 2;
	}
    }

    if (detach(pid))
    {
	WARN("Unable to detach from %d.\n", pid);
	return 3;
    };

    return 0;
}

int read_string(char **buffer, int pid, Elf64_Addr addr)
{
    int len = 0, i;
    char byte;

    if (attach(pid))
    {
	WARN("Unable to attach to %d.\n", pid);
        return 1;
    };

    while (!read_byte(&byte, pid, addr + len) && byte) len++;

    *buffer = malloc(len + 1);
    if (!buffer)
    {
	WARN("read string malloc error.\n");
	return 2;
    }

    for (i = 0; i < len; i++) {
	if (read_byte((*buffer + i), pid, addr + i)) {
	    WARN("read string error.\n");
	    return 3;
	}
    }
    *(*buffer + i) = '\0';

    if (detach(pid))
    {
	WARN("Unable to detach from %d.\n", pid);
    };

    return 0;
}

/* Signaling functions */
int stop(int pid)
{
    return kill(pid, SIGSTOP);
}

int restart(int pid)
{
    return kill(pid, SIGCONT);
}

/* attach/detach and run functions */
int attach(int pid)
{
    int status;

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL))
    {
	WARN("PTRACE_ATTACH error.\n");
	return 1;
    }

    usleep(1000);
    if (waitpid(-1, &status, __WALL) == -1) {
	WARN("waitpid error (pid %d).\n", pid);
	return 2;
    }

    return 0;
}

int detach(int pid)
{
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL))
    {
	WARN("PTRACE_DETACH error.\n");
	return 1;
    }
    return 0;
}

int get_regs(int pid, struct user_regs_struct *regs)
{
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs))
    {
	WARN("PTRACE_GETREGS error.\n");
	return 1;
    }
    return 0;
}

int set_regs(int pid, struct user_regs_struct *regs)
{
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs))
    {
	WARN("PTRACE_SETREGS error.\n");
	return 1;
    }
    return 0;
}

int run_and_redirect(int pid, struct user_regs_struct *regs, Elf64_Addr addr)
{
    int status;

    if (attach(pid))
    {
	WARN("Unable to attach to %d.\n", pid);
	return 1;
    };

    if (ptrace(PTRACE_SETREGS, pid, NULL, regs))
    {
	WARN("PTRACE_SETREGS error (pid %d).\n", pid);
	return 2;
    }

    if (ptrace(PTRACE_CONT, pid, NULL, NULL))
    {
	WARN("PTRACE_CONT error (pid %d).\n", pid);
	return 3;
    }

    usleep(1000);
    if (waitpid(-1, &status, __WALL) == -1)
    {
	WARN("waitpid error (pid %d).\n", pid);
	return 4;
    }

    if (WIFEXITED(status) || WCOREDUMP(status))
    {
	WARN("%d failed %s.\n", pid, strsignal(WEXITSTATUS(status)));
	return 5;
    }

    if (!WIFSTOPPED(status))
    {
	WARN("Target %d did not stop.\n", pid);
	return 6;
    }

    if (ptrace(PTRACE_GETREGS, pid, NULL, regs))
    {
	WARN("PTRACE_GETREGS error (pid %d).\n", pid);
	return 7;
    }

    regs->rip = addr;

    if (ptrace(PTRACE_SETREGS, pid, NULL, regs))
    {
	WARN("PTRACE_GETREGS error (pid %d).\n", pid);
	return 8;
    }

    if (detach(pid))
    {
	WARN("Unable to detach from %d.\n", pid);
	return 9;
    };

    return 0;
}
