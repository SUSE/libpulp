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
child = pexpect.spawn('./numserv', timeout=1, env=preload,
                      encoding='utf-8')
child.logfile = sys.stdout

child.expect('Waiting for input.')
print('Greeting... ok.')

child.sendline('dozen')
child.expect('12');
print('First call to libdozens... ok.')

# Apply live patch and check for new behavior
ret = subprocess.run([trigger, '-p', str(child.pid),
                     'libdozens_livepatch99.ulp'])
if ret.returncode:
  print('Failed to apply livepatch #99 for libdozens')
  exit(1)

child.sendline('dozen')
index = child.expect(['13', '12']);
print('Second call to libdozens... ', end='')
if index == 0:
  print('ok.')
if index == 1:
  print('not ok; old behavior.')
  exit (1)

# Try to terminate the child normally, otherwise kill it
child.sendline('quit')
ret = child.expect('Quitting.')
if ret == 0:
  print('Quit... ok.')
  exit(0)
else:
  print('Failed to quit the test program.')
  child.close(force=True)
  exit(1)
