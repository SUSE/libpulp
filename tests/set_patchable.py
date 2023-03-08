
#!/usr/bin/env python3

#   libpulp - User-space Livepatching Library
#
#   Copyright (C) 2020-2023 SUSE Software Solutions GmbH
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

import re

import testsuite

# Live patch selection variable
child = testsuite.spawn('numserv')

child.expect('Waiting for input.')

child.sendline('dozen')
child.expect('12');

child.sendline('hundred')
child.expect('100');

child.livepatch('.libs/libdozens_livepatch1.so')

child.sendline('dozen')
child.expect('13', reject='12');

child.sendline('hundred')
child.expect('100');

child.disable_livepatching()
child.livepatch('.libs/libhundreds_livepatch1.so', sanity=False)

child.sendline('dozen')
child.expect('13', reject='12');

child.sendline('hundred')
child.expect('100', reject='200');

child.enable_livepatching()
child.livepatch('.libs/libhundreds_livepatch1.so')

child.sendline('hundred')
child.expect('200', reject='100');

child.close(force=True)
exit(0)
