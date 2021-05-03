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

child = testsuite.spawn('redzone', timeout=10)

child.expect('Waiting for input.')

child.livepatch('libblocked_livepatch1.ulp')

# Check live patch, which should not touch the redzone
child.is_patch_applied('libblocked_livepatch1.ulp')

# Read error output, if any
child.readline()
child.readline()

ret = child.wait()
if ret:
  exit(1)
exit(0)
