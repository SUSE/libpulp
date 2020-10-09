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
import subprocess
import sys

# ULP tools location
builddir = os.getcwd()
trigger = builddir + '/../tools/trigger/ulp_trigger'
check = builddir + '/../tools/trigger/ulp_check'
preload = {'LD_PRELOAD': builddir + '/../lib/.libs/libpulp.so'}

# Test case name
testname = os.path.splitext(sys.argv[0])
testname = os.path.basename(testname[0])

# Start the test program
child = pexpect.spawn('./' + testname, timeout=10, env=preload,
                      encoding='utf-8')
child.logfile = sys.stdout

child.expect('Waiting for input.')
print('Greeting... ok.')

# Apply live patch, which should not touch the redzone
ret = subprocess.run([trigger, str(child.pid),
                     'libblocked_livepatch1.ulp'])
if ret.returncode:
  print('Failed to apply livepatch #1 for libblocked')
  exit(1)

# Check live patch, which should not touch the redzone
ret = subprocess.run([check, str(child.pid),
                     'libblocked_livepatch1.ulp'])
if ret.returncode:
  print('Failed to check livepatch status')
  exit(1)

# Read error output, if any
child.readline()
child.readline()

ret = child.wait()
if ret:
  exit(1)
exit(0)
