/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2020 SUSE Software Solutions GmbH
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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/syscall.h>

void foo(int n) {
    fprintf(stderr, "[THREAD %lu] ", syscall(SYS_gettid));
    fprintf(stderr, "example: foo %d\n", n);
}

int bar() {
    fprintf(stderr, "[THREAD %lu] ", syscall(SYS_gettid));
    fprintf(stderr, "example: locked behind bars...\n");
    foo(3);
    return 1;
}

int sleeping_bar(int time) {
    fprintf(stderr, "[THREAD %lu] ", syscall(SYS_gettid));
    fprintf(stderr, "example: locked behind sleepin' bars...\n");
    sleep(time);
    return 1;
}

int loop_bar(int time) {
    while(sleeping_bar(time)) { sleep(rand() % 5); }
    fprintf(stderr, "[THREAD %lu] ", syscall(SYS_gettid));
    fprintf(stderr, "leaving loop_bar\n");
    return 1;
}

int eternal_sleeper_bar(int time) {
    while (1) {
    //   fprintf(stderr, "[THREAD %lu] ", syscall(SYS_gettid));
       sleeping_bar(time);
    }
    return 1;
}
