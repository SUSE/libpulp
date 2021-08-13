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

#include <errno.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>

int
main(void) {
    pid_t pid;

    pid = fork();
    
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
            perror("critical_section_verification");
            return 1;
        }

        while(1);
    }
    else if (pid > 0) {
        if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
            perror("critical_section_verification");
            return 1;
        }

        while(1);
    }
    else {
        perror("critical_section_verification");
        return 1;
    }

}