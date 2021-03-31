#!/usr/bin/env python3

#   libpulp - User-space Livepatching Library
#
#   Copyright (C) 2021 SUSE Software Solutions GmbH
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

from tests import *

# Start the test program and check default behavior
child = pexpect.spawn('./contract', timeout=1, env=preload,
                      encoding='utf-8')
child.logfile = sys.stdout

child.expect('Waiting for input.')
print('Greeting ok.')

errors = 0
child.sendline('')
print('Inside the library, waiting for further input.')
child.sendline('')
child.expect('TYPE A data 128\r\n');
print('Still inside the library, waiting for further input.')
child.sendline('')
child.expect('TYPE B data 256.000000\r\n');
print('Behavior prior to live patching ok.')

# Send the test program into the library.
child.sendline('')
print('Inside the library, waiting for further input.')

# Apply live patch while inside library
print('Applying live patch.')
ret = subprocess.run([trigger, str(child.pid),
                      'libcontract_livepatch1.ulp'])
if ret.returncode:
  print('Failed to apply livepatch #1 for libcontract')
  exit(1)

# Let the process resume and check fna behavior
child.sendline('')
index = child.expect(['TYPE A data 128\r\n', 'Invalid type.\r\n',
                      pexpect.TIMEOUT]);
if index == 0:
  print('Behavior of fna after live patching... ok.')
if index == 2:
  print('Behavior of fna after live patching... error.')
  errors = 1
if index == 3:
  print('Behavior of fna after live patching... timedout.')
  errors = 1

# Let the process resume and check fnb behavior
print('Still inside the library, waiting for further input.')
child.sendline('')
index = child.expect(['TYPE B data 1024.000000\r\n', 'Invalid type.\r\n',
                      pexpect.TIMEOUT]);
if index == 0:
  print('Behavior of fnb after live patching... ok.')
if index == 2:
  print('Behavior of fnb after live patching... error.')
  errors = 1
if index == 3:
  print('Behavior of fnb after live patching... timedout.')
  errors = 1

# Kill the child process and exit
child.close(force=True)
exit(errors)
