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

from tests import *

# Start the test program and check default behavior
child = pexpect.spawn('./numserv', timeout=1, env=preload)

child.expect('Waiting for input.')
print('Greeting... ok.')

child.sendline('hundred')
child.expect('100');
print('First call to libhundreds... ok.')

# Apply first live patch
ret = subprocess.run([trigger, str(child.pid),
                     'libhundreds_livepatch1.ulp'], timeout=20)
if ret.returncode:
  print('Failed to apply livepatch #1 for libhundreds')
  exit(1)

child.sendline('hundred')
index = child.expect(['200', '100']);
print('Second call to libhundreds... ', end='')
if index == 0:
  print('ok.')
if index == 1:
  print('not ok; old behavior.')
  exit (1)

# Apply second live patch
ret = subprocess.run([trigger, str(child.pid),
                     'libhundreds_livepatch2.ulp'], timeout=20)
if ret.returncode:
  print('Failed to apply livepatch #2 for libhundreds')
  exit(1)

child.sendline('hundred')
index = child.expect(['300', '100', '200']);
print('Third call to libhundreds... ', end='')
if index == 0:
  print('ok.')
if index == 1 or index == 2:
  print('not ok; old behavior.')
  exit (1)

# Revert the second live patch
ret = subprocess.run([trigger, str(child.pid),
                     'libhundreds_livepatch2.rev'], timeout=20)
if ret.returncode:
  print('Failed to revert livepatch #2 for libhundreds')
  exit(1)

child.sendline('hundred')
index = child.expect(['200', '100', '300']);
print('Fourth call to libhundreds... ', end='')
if index == 0:
  print('ok.')
if index == 1 or index == 2:
  print('not ok; old behavior.')
  exit (1)

# Revert the first live patch
ret = subprocess.run([trigger, str(child.pid),
                     'libhundreds_livepatch1.rev'], timeout=20)
if ret.returncode:
  print('Failed to revert livepatch #1 for libhundreds')
  exit(1)

child.sendline('hundred')
index = child.expect(['100', '200', '300']);
print('Fifth call to libhundreds... ', end='')
if index == 0:
  print('ok.')
if index == 1 or index == 2:
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
