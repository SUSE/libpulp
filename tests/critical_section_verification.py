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

from subprocess import CalledProcessError

import testsuite


import subprocess
subprocess.run(["ls", "-l"])

child = testsuite.spawn('critical_section_verification', log=None)

# Exec function which calls ptrace on to-be-patched process

try:
    child.livepatch('libhundreds_livepatch1.ulp')
    ret = 0
except CalledProcessError:
    ret = 1

child.close(force=True)  # TODO: Verify okay here

exit(ret)