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

import subprocess
import time

import testsuite

child = testsuite.spawn('blocked')

# Wait for both threads to be ready (the order does not matter)
child.expect('Waiting for signals.')
child.expect('Waiting for signals.')

# The ulp tool reads the thread-local counter from every thread in live
# patchable processes. It must not break the process.
try:
  subprocess.run([testsuite.ulptool, '-p', str(child.pid)])
except:
  # Testing whether the ulp tool works or not is not the intent of this test
  # case, so forward a hard error to the test harness..
  child.close(force=True)
  exit(99)

# Kill the child process and exit
time.sleep(1)
if child.isalive():
  child.close(force=True)
  exit(0)
else:
  print('Live patchable process died')
  exit(1)
