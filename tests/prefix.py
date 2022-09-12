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
#
# This test checks if passing the -R option to trigger with a silly
# prefix causes the patching to fail on libpulp.so side.  This is
# useful if ulp runs in a chroot.

import testsuite
import re

child = testsuite.spawn('prefix')

child.expect('Waiting for input.')

child.sendline('hundred')
child.expect('100')

child.livepatch('.libs/libprefix_livepatch1.so', prefix="/silly-prefix/", sanity=False)

msgs = child.get_libpulp_messages()
if re.search(r'Unable to load shared object /silly-prefix/.*/.libs/libprefix_livepatch1.so', msgs):
  error = 0
else:
  error = 1

child.close(force=True)
exit(error)
