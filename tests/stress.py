#!/usr/bin/env python3
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

# This test stress out the ulp tool when multiple processes are running.

import sys
import testsuite
import subprocess

child = testsuite.spawn('stress')
child.expect("Processes launched")

testsuite.childless_livepatch(wildcard='.libs/libstress_livepatch1.so', verbose=False, timeout=60)

child.expect("Processes finished", reject=['returned non-zero'])
child.close(force=True)
