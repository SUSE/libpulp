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
child = pexpect.spawn('./' + testname, timeout=1, env=preload,
                      encoding='utf-8')

# Wait for the test program to be ready
child.expect('Waiting for signals.\r\n')

# Check default output
print('Testing output before live patch... ', end='')
child.kill(signal.SIGUSR1)
child.expect('hello\r\n')
print('ok.')

errors = 0
try:
  # Apply the live patch.
  ret = subprocess.run([trigger, str(child.pid),
                        'libblocked_livepatch1.ulp'], timeout=1)
  if ret.returncode:
    print('Failed to apply livepatch #1 for libblocked')
    errors = 1
except subprocess.TimeoutExpired:
  print('Deadlock reached when appling livepatch', end='')
  print(' - AS-Unsafe conversion left untested')
  # The deadlock test (tests/deadlock) has a far greater chance of
  # detecting deadlocks during the application of live-patches, so
  # return 77 to report that this test case was unable to detect the
  # AS-Unsafe conversion.
  errors = 77
else:
  # Send signals to the process which will cause the live-patched
  # function to be called from the context of a signal-handler. If the
  # live-patched function became AS-Unsafe, it might deadlock. Since it
  # is not guaranteed to deadlock every time, loop it an arbitrarily
  # chosen number of times
  print('Testing that calling the live-patched function ', end='')
  print('from a signal handler does not deadlock: ')
  for attempt in range(1000):
    print('\r' + str(attempt), end='')
    child.kill(signal.SIGUSR1)
    index = child.expect(['hello_world\r\n', pexpect.TIMEOUT])
    if index == 1:
      errors = 1
      break
  if index == 0:
    print(' - ok')
  else:
    print(' - deadlock reached (AS-Unsafe conversion)')
finally:
  # Always kill the child process
  child.close(force=True)

# Kill the child process and exit
child.close(force=True)
exit(errors)
