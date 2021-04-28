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

import testsuite

child = testsuite.spawn('syscall_restart')

child.expect('Waiting for input.')

# After printing the greeting message, the target process makes a call
# to fgets, which calls the read syscall. Applying a live patch will
# interrupt the syscall.
child.livepatch('libparameters_livepatch1.ulp')

# Send a newline, which should be received by the read syscall if it has
# been successfully restarted by libpulp. If the syscall has not been
# restarted, the child program will exit without printing anything.
child.sendline('')
child.expect('8-7-6-5-4-3-2-1');
child.expect('10.0-9.0-8.0-7.0-6.0-5.0-4.0-3.0-2.0-1.0');

child.close(force=True)
exit(0)
