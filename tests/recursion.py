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
child = pexpect.spawn('./' + testname, timeout=60, env=preload,
                      encoding='utf-8')
child.logfile = sys.stdout

print('Greeting... ', end='')
child.expect('Waiting for input.\r\n')
print('ok.')

print('Fibonacci... ', end='')
child.sendline('45')
child.expect('1134903170\r\n');
print('ok.')

# Apply live patch and check for new behavior
ret = subprocess.run([trigger, str(child.pid),
                      'librecursion_livepatch1.ulp'])
if ret.returncode:
  print('Failed to apply livepatch #1 for librecursion')
  exit(1)

print('Lucas... ', end='')
child.sendline('45')
child.expect('2537720636\r\n');
print('ok.')

# Kill the child process and exit
child.close(force=True)
exit(0)
