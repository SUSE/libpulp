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

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int
main(int argc, char **argv, char **envp)
{
  int pid;
  int status;

  if (argc < 2) {
    printf("Usage: %s <subprogram>.\n", argv[0]);
    return 1;
  }

  /* Signal readiness. */
  printf("Parent ready\n");
  fflush(stdout);

  /* Mimic a terminal by forking a new process and waiting for it. */
  if ((pid = fork())) {
    if (waitpid(pid, &status, WUNTRACED | WCONTINUED) == -1)
      perror("terminal");
    if(WIFSTOPPED(status))
      printf("Child stopped with %d.\n", WSTOPSIG(status));
    if(WIFCONTINUED(status))
      printf("Child continued.\n");
    return 7;
  }
  else
    execve(argv[1], argv, envp);

  return 0;
}
