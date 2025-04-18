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

import testsuite
import subprocess


childs = [testsuite.spawn('manyprocesses'),
          testsuite.spawn('manyprocesses'),
          testsuite.spawn('manyprocesses')]

for child in childs:
    child.expect('Waiting for input.')

    child.sendline('')
    child.expect('1-2-3-4-5-6-7-8');
    child.expect('1.0-2.0-3.0-4.0-5.0-6.0-7.0-8.0-9.0-10.0');

# Try to livepatch everything into the manyprocesses.
output = testsuite.childless_livepatch(wildcard='.libs/*_livepatch1.so',
                                       verbose=True,
                                       revert_lib='libmanyprocesses.so.0',
                                       capture_output=True)

# Check if the patched counter is correct.
if output.find("Processes patched: 3") == -1:
    exit(1)


for child in childs:
    child.sendline('')
    child.expect('10-9-8-7-6-5-4-3-2-1', reject='1-2-3-4-5-6-7-8-9-10');
    child.expect('10.0-9.0-8.0-7.0-6.0-5.0-4.0-3.0-2.0-1.0',
                 reject='1.0-2.0-3.0-4.0-5.0-6.0-7.0-8.0-9.0-10.0');

testsuite.childless_livepatch(wildcard=None, verbose=True, revert_lib='libmanyprocesses.so.0')

for child in childs:
    child.sendline('')
    child.expect('1-2-3-4-5-6-7-8-9-10', reject='10-9-8-7-6-5-4-3-2-1');
    child.expect('1.0-2.0-3.0-4.0-5.0-6.0-7.0-8.0-9.0-10.0',
                 reject='10.0-9.0-8.0-7.0-6.0-5.0-4.0-3.0-2.0-1.0');

    child.close(force=True)
