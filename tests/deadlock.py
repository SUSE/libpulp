#!/usr/bin/env python3

import os
import pexpect
import re
import signal
import subprocess
import sys

# ULP tools location
builddir = os.getcwd()
trigger = builddir + '/../tools/trigger/ulp_trigger'
preload = {'LD_PRELOAD': builddir + '/../lib/.libs/libulp.so'}

# Test case name and live patch selection variable
testname = os.path.splitext(sys.argv[0])
testname = os.path.basename(testname[0])

# Start the test program
child = pexpect.spawn('./' + testname, timeout=1, env=preload,
                      encoding='utf-8')
child.logfile = sys.stdout
errors = 0

# Wait for the test program to be ready
child.expect('Waiting for signals.\r\n')

# Applying a live patch to a process entails stopping all of its
# threads, then stealing one of them to jack into the process and call
# libulp.so's routines that load and apply the live patch. These
# routines are called from the context of a signal-handler, and, as
# such, should not make calls to Asynchronous Signal Unsafe (AS-Unsafe)
# functions. However, push_new_detour uses calloc, which might lead to
# the deadlock demonstrated with this test case.
try:
  ret = subprocess.run([trigger, str(child.pid),
                        'libblocked_livepatch1.ulp'], timeout=1)
  if ret.returncode:
    print('Failed to apply livepatch #1 for libblocked')
    errors = 1
except subprocess.TimeoutExpired:
  print('Deadlock reached when appling livepatch')
  errors = 1

# The deadlock mentioned above is not guaranteed to happen every time.
# This loop causes the test case to call calloc from a signal-handler
# until the deadlock can be observed, and only so that it can always be
# observed and that the test case does not fail with XPASS.
#
# TODO: When the deadlock problem during live patch installation gets
#       fixed, remove this block (or do not set errors to 1).
index = 0
while index == 0:
  child.kill(signal.SIGUSR1)
  child.expect('handler entry')
  print('Signal handler reached... ok.')
  index = child.expect(['handler exit', pexpect.TIMEOUT])
  if index == 0:
    print('Signal handler exited... no deadlock.')
  if index == 1:
    print('Signal handler timed out... deadlock.')
    errors = 1

# Kill the child process and exit
child.close(force=True)
exit(errors)
