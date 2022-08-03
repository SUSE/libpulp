#!/usr/bin/env python3

#   libpulp - User-space Livepatching Library
#
#   Copyright (C) 2020-2022 SUSE Software Solutions GmbH
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

error = 1

child = testsuite.spawn('comments', script=False)

child.expect('Ready.')
child.livepatch('.libs/libcomments_livepatch1.so')
child.expect('Livepatched');

try:
    msgs = child.get_patches()
    if msgs.find('bsc#1200316') != -1 and msgs.find('jsc#SLE-20049') != -1 and msgs.find('CVE-2021-3449') != -1:
        error = 0
except:
    print("Bug labels not found.")
    error = 1

child.close(force=True)
exit(error)
