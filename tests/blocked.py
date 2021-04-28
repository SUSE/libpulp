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

import testsuite

child = testsuite.spawn('blocked')

# Wait for both threads to be ready (the order does not matter)
child.expect('Waiting for signals.')
child.expect('Waiting for signals.')

# At program start, two threads are put into loops waiting for signals,
# thread1 waits for SIGUSR1 and thread2 waits for SIGUSR2.
child.kill(signal.SIGUSR1)
child.expect('hello')
child.kill(signal.SIGUSR2)
child.expect('hello')

# After the live patching, thread1, which is looping outside the
# library, should produce a different output, whereas thread2, which
# never leaves the library, should display the  old behavior.
child.livepatch('libblocked_livepatch1.ulp')

child.kill(signal.SIGUSR1)
child.expect('hello_world')
child.kill(signal.SIGUSR2)
child.expect('hello')

child.close(force=True)
exit(0)
