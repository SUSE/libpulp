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

child = testsuite.spawn('numserv')

child.expect('Waiting for input.')

child.sendline('hundred')
child.expect('100')

child.livepatch('.libs/libhundreds_livepatch1.so')

child.sendline('hundred')
child.expect('200', reject='100')

# Now try to patch a wrong file but revert all patches associated with
# libhundred. If there is a fail on apply and revert-all is specified,
# it shoudn't revert the livepatches. That could imply in unsecure
# code being run.

try:
  child.livepatch('.libs/libnonexistent_livepatch1.so', revert_lib="libhundreds.so.0", sanity=False)
except:
  pass

child.sendline('hundred')
child.expect('200', reject='100')
exit(0)
