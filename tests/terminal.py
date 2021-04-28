#!/usr/bin/env python3

#   libpulp - User-space Livepatching Library
#
#   Copyright (C) 2020-2021 SUSE Software Solutions GmbH
#
#   This file is part of libpulp.
#
#   libpulp is free software; you can redistribute it and/or
#   modify it under the terms of the GNU Lesser General Public
#   License as published by the Free Software Foundation; either
#   version 2.1 of the License, or (at your option) any later version.
#
#   libpulp is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#   Lesser General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with libpulp.  If not, see <http://www.gnu.org/licenses/>.

import os
import subprocess
import time

import testsuite
from testsuite import checker

parent = testsuite.spawn('./terminal ./loop')

# Parent signal readiness first
parent.expect('Parent ready')

# Read the pid of the child process, which wrote it to stdout
parent.expect('Child ready')
parent.expect('[0-9]+\r\n')
pid = parent.after # XXX: Missing input validation

# If live patching SIGSTOPs the target process, the parent detects it
# with waitpid, but only most of the time. If the trigger and check
# tools also send SIGCONT quickly after SIGSTOP, the detection doesn't
# always work, so try it an arbitrarily large number of times.
errors = 0
for i in range(32):

  # Use the Check tool to attach and detach to the child process. Notice
  # that, unlike other test cases, this child process has not been
  # started by the testing framework. Rather, it has been forked from
  # its parent (terminal.c), thus, child.is_patch_applied and
  # child.livepatch cannot be used.
  ret = subprocess.run([checker, '-q', '-p', pid, 'libblocked_livepatch1.ulp'])
  # The Check tool returns 0 when the given live patch has not been
  # applied, which is the expected output here. Anything else is treated
  # as a hard error (99), because detecting errors in the Check tool
  # itself is not the intent of this test case.
  if ret.returncode:
    print('Unexpected error while using ulp tools')
    errors = 99
    break
  else:
    print('Check OK')

  # Wait a while so that the parent process has a chance to detect
  # SIGSTOP/SIGCONT and exit normally with exit status 7, a magic
  # number. Other codes are unexpected and treated as hard error (99).
  time.sleep(0.1)
  if parent.isalive() == False:
    if parent.exitstatus == 7:
      print('Parent detected SIGSTOP/SIGCONT and exited')
    else:
      print('Unknown cause for parent termination')
      errors = 99
    break

# Kill the parent process
parent.close(force=True)
if parent.exitstatus == 7:
  if errors == 0:
    errors = 1

# Guarantee the child process gets killed
try:
  os.kill(int(pid), signal.SIGKILL)
except:
  print('Failed to kill forked process. Already dead?')

exit(errors)
