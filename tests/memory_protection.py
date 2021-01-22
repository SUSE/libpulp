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
child = pexpect.spawn('./' + testname, timeout=1, env=preload,
                      encoding='utf-8')

child.expect('Waiting for input.')
print('Greeting... ok.')

# Every time a newline is sent, the test program touchs code memory
print('Testing output before live patch... ', end='')
child.sendline('')
child.expect('Non-NULL\r\n');
print('ok.')

# Apply live patch
print('Applying live patch... ', end='')
ret = subprocess.run([trigger, str(child.pid),
                      'libaddress_livepatch1.ulp'])
if ret.returncode:
  print('fail.')
  exit(1)
print('ok.')

# Try to touch code memory after live patching
print('Testing output after live patch... ', end='')
child.sendline('')
index = child.expect(['NULL\r\n', pexpect.EOF]);
if index == 0:
  print('ok.')
if index == 1:
  print('fail.')
  if child.isalive() == False:
    print('Test program is dead')
  exit(1)

# Kill the child process and exit
child.close(force=True)
exit(0)
