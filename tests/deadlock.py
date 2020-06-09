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

# Since the deadlock demonstrated by this test case does not occur
# everytime it executes, run it in a loop. The amount of iterations
# hardcoded is arbitrary
errors = 0
for attempt in range(32):
  # Start the test program
  child = pexpect.spawn('./' + testname, timeout=20, env=preload,
                        encoding='utf-8')

  # Wait for the test program to be ready
  child.expect('Waiting for input.\r\n')

  # Check default behavior
  print('Testing output before live patch... ', end='')
  child.sendline('')
  child.expect('hello\r\n')
  print('OK.')

  # Applying a live patch to a process entails stopping all of its
  # threads, then stealing one of them to jack into the process and call
  # libulp.so's routines that load and apply the live patch. These
  # routines are called from the context of a signal-handler, and, as
  # such, should not make calls to Asynchronous Signal Unsafe functions.
  # However, libulp calls dlopen, which is AS-Unsafe.
  try:
    ret = subprocess.run([trigger, str(child.pid),
                          'libblocked_livepatch1.ulp'], timeout=20)
    if ret.returncode:
      print('Failed to apply livepatch #1 for libblocked')
      errors = 1
  except subprocess.TimeoutExpired:
    print('Deadlock reached when appling livepatch')
    errors = 1
  else:
    # Check that the livepatch was applied correctly
    print('Testing output after live patch... ', end='')
    child.sendline('')
    child.expect('hello_world\r\n')
    print('OK.')
  finally:
    # Always kill the child process
    child.close(force=True)

  # Stop the loop at the first time the deadlock occurs.
  if errors:
    break

exit(errors)
