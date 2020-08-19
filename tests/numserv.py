#!/usr/bin/env python3

import os
import pexpect
import re
import subprocess
import sys

# ULP tools location
builddir = os.getcwd()
trigger = builddir + '/../tools/trigger/ulp_trigger'
preload = {'LD_PRELOAD': builddir + '/../lib/.libs/libpulp.so'}

# Test case name and live patch selection variable
testname = os.path.splitext(sys.argv[0])
testname = os.path.basename(testname[0])
bsymbolic = re.search('_bsymbolic', testname)

# Start the test program and check default behavior
child = pexpect.spawn('./' + testname, timeout=1, env=preload)

child.expect('Waiting for input.')
print('Greeting... ok.')

child.sendline('dozen')
child.expect('12');
print('First call to libdozens... ok.')

child.sendline('hundred')
child.expect('100');
print('First call to libhundreds... ok.')

# Apply live patch and check for new behavior
ret = subprocess.run([trigger, str(child.pid),
                     'libdozens_livepatch1.ulp' if not bsymbolic else
                     'libdozens_bsymbolic_livepatch1.ulp'])
if ret.returncode:
  print('Failed to apply livepatch #1 for libdozens')
  exit(1)

child.sendline('dozen')
index = child.expect(['13', '12']);
print('Second call to libdozens... ', end='')
if index == 0:
  print('ok.')
if index == 1:
  print('not ok; old behavior.')
  exit (1)

child.sendline('hundred')
child.expect('100');
print('Second call to libhundreds... ok.')

# Apply live patch and check for new behavior
ret = subprocess.run([trigger, str(child.pid),
                     'libhundreds_livepatch1.ulp' if not bsymbolic else
                     'libhundreds_bsymbolic_livepatch1.ulp'])
if ret.returncode:
  print('Failed to apply livepatch #1 for libhundreds')
  exit(1)

child.sendline('dozen')
index = child.expect(['13', '12']);
print('Third call to libdozens... ', end='')
if index == 0:
  print('ok.')
if index == 1:
  print('not ok; old behavior.')
  exit (1)

child.sendline('hundred')
child.expect(['200', '100']);
print('Third call to libhundreds... ', end='')
if index == 0:
  print('ok.')
if index == 1:
  print('not ok; old behavior.')
  exit (1)

# Try to terminate the child normally, otherwise kill it
child.sendline('quit')
ret = child.expect('Quitting.')
if ret == 0:
  print('Quit... ok.')
  exit(0)
else:
  print('Failed to quit the test program.')
  child.close(force=True)
  exit(1)
