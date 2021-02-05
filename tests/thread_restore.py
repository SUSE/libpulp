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

from tests import *

# Start the test program and check default behavior
child = pexpect.spawn('./blocked', timeout=1, env=preload,
                      encoding='utf-8')
child.logfile = sys.stdout

# Wait for both threads to be ready (the order does not matter)
child.expect('Waiting for signals.\r\n')
child.expect('Waiting for signals.\r\n')

# The ulp tool reads the thread-local counter from every thread in live
# patchable processes. It must not break the process.
ret = subprocess.run([ulp, '-p', str(child.pid)])
if ret.returncode:
  print('Unable to run ulp tool')
  exit(1)

# Kill the child process and exit
time.sleep(1)
if child.isalive():
  exit(0)
else:
  print('Live patchable process died')
  exit(1)
