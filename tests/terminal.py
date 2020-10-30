#!/usr/bin/env python3

#   libpulp - User-space Livepatching Library
#
#   Copyright (C) 2020 SUSE Software Solutions GmbH
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
import pexpect
import re
import signal
import subprocess
import sys
import time

# ULP tools location
builddir = os.getcwd()
check = builddir + '/../tools/trigger/ulp_check'

# Start the test program
parent = pexpect.spawn('./terminal ./loop', timeout=10, encoding='utf-8')
parent.logfile = sys.stdout

# Parent signal readiness first
parent.expect('Parent ready\r\n')

# Read the pid of the child process, which wrote it to stdout
parent.expect('Child ready\r\n')
parent.expect('[0-9]+\r\n')
pid = parent.after

# If live patching SIGSTOPs the target process, the parent detects it
# with waitpid, but only most of the time. If the trigger and check
# tools also send SIGCONT quickly after SIGSTOP, the detection doesn't
# always work, so try it an arbitrarily large number of times.
errors = 0
for i in range(32):

  # Attach and detach with ulp tools
  ret = subprocess.run([check, pid, 'libblocked_livepatch1.ulp'])
  if ret.returncode:
    print('Failed to check livepatch #1 for libblocked')
    print('(error not related to SIGSTOP/SIGCONT detection)')
    errors = 77
    break
  else:
    print('Check OK')

  # Wait a while so that the parent process has a chance to detect
  # SIGSTOP/SIGCONT and exit normally, then verify it.
  time.sleep(0.1)
  if parent.isalive() == False:
    if parent.exitstatus == 7:
      print('Parent detected SIGSTOP/SIGCONT and exited')
    else:
      print('Hard error: unknown cause for parent termination')
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
