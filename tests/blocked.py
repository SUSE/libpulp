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

# Start the test program and check default behavior
child = pexpect.spawn('./' + testname, timeout=1, env=preload,
                      encoding='utf-8')
child.logfile = sys.stdout

# Wait for both threads to be ready (the order does not matter)
child.expect('Waiting for signals.\r\n')
child.expect('Waiting for signals.\r\n')

# At program start, two threads are put into loops waiting for signals,
# thread1 waits for SIGUSR1 and thread2 waits for SIGUSR2.
child.kill(signal.SIGUSR1)
child.expect('hello\r\n')
print('Thread #1... ok.')
child.kill(signal.SIGUSR2)
child.expect('hello\r\n')
print('Thread #2... ok.')

# After the live patching, thread1, which is looping outside the
# library, should produce a different output, whereas thread2, which
# never leaves the library, should display the  old behavior.
ret = subprocess.run([trigger, str(child.pid),
                      'libblocked_livepatch1.ulp'])
if ret.returncode:
  print('Failed to apply livepatch #1 for libblocked')
  exit(1)
child.kill(signal.SIGUSR1)
child.expect('hello_world\r\n')
print('Thread #1... ok.')
child.kill(signal.SIGUSR2)
child.expect('hello\r\n')
print('Thread #2... ok.')

# Kill the child process and exit
child.close(force=True)
exit(0)
