#!/usr/bin/env python3

#   libpulp - User-space Livepatching Library
#
#   Copyright (C) 2020-2024 SUSE Software Solutions GmbH
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

child = testsuite.spawn('visibility', script=False)

child.expect('Press ENTER to continue')
child.sendline('')
child.expect('This is a hidden string')
child.expect('Press ENTER to continue')
out = child.livepatch('.libs/libvisibility_livepatch1.so',
                sanity=False, capture_tool_output=True)

child.sendline('')
child.expect('This is a hidden string')

# Check if we can't apply the above patch.
if out.find('Failure in dlopen') < 0:
  child.close(force=True)
  exit(1)

# Now try to apply the patch with strong externalization
child.expect('Press ENTER to continue')
child.livepatch('.libs/libvisibility_livepatch2.so')

child.sendline('')
child.expect('String from lp This is a hidden string')

child.close(force=True)
exit(0)
