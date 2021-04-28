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

import signal
import subprocess

import testsuite

child = testsuite.spawn('asunsafe_conversion')

child.expect('Waiting for signals.')

child.kill(signal.SIGUSR1)
child.expect('hello')

errors = 0
try:
  # Apply the live patch.
  child.livepatch('libblocked_livepatch1.ulp', retries=100)
except subprocess.TimeoutExpired:
  print('Deadlock while live patching - AS-Unsafe conversion not tested')
  # The deadlock test (tests/deadlock) has a far greater chance of
  # detecting deadlocks during the application of live-patches, so
  # return 77 to report that this test case was unable to detect the
  # AS-Unsafe conversion.
  errors = 77
except subprocess.CalledProcessError as err:
  # The trigger tool may fail to apply a live patch when the locks it
  # needs to acquire from glibc are busy. This is expected to happen
  # some times, but not the intent of this test case, so return 77 to
  # report that the AS-Unsafe conversion was not properly detected.
  if err.returncode == 1:
    print('Unable to live patch - AS-Unsafe conversion not tested')
    errors = 77
  # On the other hand, if the trigger tool fails for some unexpected
  # reason, signal it as a hard error (99) to the test harness.
  else:
    print('Unexpected failure while live patching')
    errors = 99
else:
  # Send signals to the process which will cause the live-patched
  # function to be called from the context of a signal-handler. If the
  # live-patched function became AS-Unsafe, it might deadlock. Since it
  # is not guaranteed to deadlock every time, loop it an arbitrarily
  # chosen number of times.
  for attempt in range(1000):
    child.kill(signal.SIGUSR1)
    try:
      child.expect('hello_world')
    except TimeoutError:
      print('AS-Unsafe conversion detected')
      errors = 1
      break

child.close(force=True)
exit(errors)
