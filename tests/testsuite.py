#!/usr/bin/env python3

#   libpulp - User-space Livepatching Library
#
#   Copyright (C) 2021 SUSE Software Solutions GmbH
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

# From standard library
import os
import pathlib
import re
import signal
import subprocess
import sys
import time

# Third-party libraries
import pexpect
import psutil

# Test case name as provided by automake tests
testname = os.path.splitext(sys.argv[0])
testname = os.path.basename(testname[0])

# Libpulp definitions
builddir = os.getcwd()
ulptool = builddir + '/../tools/ulp'

# Check if certain library is livepatchable.
def is_library_livepatchable(library):
  command = [ulptool, "livepatchable", library]

  try:
    tool = subprocess.run(command, timeout=10, stderr=subprocess.STDOUT)
  except subprocess.TimeoutExpired:
    print('ulp tool deadlock');
    return False

  if tool.returncode == 0:
    return True
  return False

# Wrapper around pexpect.spawn that automatically sets userspace livepatching
# requirements, such as LD_PRELOAD'ing libpulp.so, as well as extends its
# functionality with live patching operations.
#
# Using this testing framework requires few steps: importing this module,
# starting a live patchable process, optionally testing its default behavior,
# applying a live patch, and testing the patched behavior, for instance:
#
#   # Import the testing framework:
#   import testsuite
#
#   # Start the target process:
#   child = testsuite.spawn('testcase')
#
#   # Check default behavior:
#   child.send('ping')
#   child.expect('pong')
#
#   # Apply a live patch
#   child.livepatch('metadata')
#
#   # Check patched behavior:
#   child.send('ping')
#   child.expect('pang')
#
# The 'livepatch' and 'expect' methods are the main interfaces to the testing
# framework. Simply calling them is usually enough, because they check for
# error conditions on their own. However, if more control over the outcomes is
# needed, they raise exceptions which can be caught and dealt with. See the
# existing test cases for examples.
class spawn(pexpect.spawn):

  # Spawn a live patchable process. Similar to pexpect.spawn, this class
  # constructor starts and controls a child process. Unlike pexpect.spawn,
  # LD_PRELOAD=libpulp.so is automatically provided, unless 'env' is passed as
  # an argument. The arguments: 'timeout', 'env' and 'encoding' are forwarded
  # to pexpect.spawn; whereas log is assigned to pexpect's logfile_read
  # attribute. Finally, 'verbose' controls whether the live patching methods
  # print messages to stdout. By default, all messages are printed, so that the
  # test suite logs contain more information for debugging.
  def __init__(self, testname, timeout=10, env=Ellipsis, log=sys.stdout,
               encoding='utf-8', verbose=True, script=True):

    # If testname is a relative path, i.e. not starting with slash, prepend
    # dot-slash to enable command-line execution.
    if testname[0] != '/':
      testname = './' + testname

    testname = '/usr/bin/sh -c ' + '\''+ testname + '\''

    # if TEST_THROUGH_VALGRIND environment variable is defined, append valgrind
    # call on testname. We actually call valgrind on the `sh` call, and it
    # still catch memory issues while avoiding libpulp problems regarding
    # the program actually being `valgrind` and not the test program.
    try:
        if os.environ['TESTS_THROUGH_VALGRIND'] == '1':
            testname = 'valgrind --leak-check=full ' + testname
    except KeyError:
        pass

    # If env has not been provided, default to LD_PRELOAD'ing libpulp.so.
    if env == Ellipsis:
      env = {'LD_PRELOAD': builddir + '/../lib/.libs/libpulp.so'}

    # Spawn the testcase with pexpect and enable logging.
    super().__init__(testname, timeout=timeout, env=env, encoding=encoding,
                     echo=False)
    self.logfile_read = log
    self.verbose = verbose

  # Print verbose messages when in verbose mode
  def print(self, *args, end=None):
    if self.verbose:
      print(*args, flush=True, end=end)

  # When pexpect.expect is unable to find the expected patterns, it prints
  # comprehensive information about the scanning status, such as the whole
  # child output, as well as less relevant information about the child process.
  # Even though the output is useful, it pollutes the test suite logs
  # unnecessarily. Thus, this class overrides expect() and always adds
  # pexpect.EOF and pexpect.TIMEOUT to the list of expected patterns, so that
  # it can print less verbose, more targeted information, when the original
  # expected patterns and the actual output do not match. If it happens, the
  # overridden method raises exceptions for EOF and Timeout, which have the
  # added benefit of displaying local, shorter, and more friendly stack traces.
  # The 'accept' and 'reject' parameters can be either single strings or lists
  # of strings, such as pexpect.expect expects.
  def expect(self, accept, reject=None):

    # Converted string arguments into lists
    if type(accept) == str:
      accept = [accept]
    if type(reject) == str:
      reject = [reject]
    if reject == None:
      reject = []

    # Valgrind always print the error summary message. Match if the errors are
    # a positive value.
    valgrind_errors = ['ERROR SUMMARY: [1-9]+ errors from',
                       'definitely lost: [1-9]+']

    reject += valgrind_errors
    valgrind_reject_index = len(reject) - len(valgrind_errors)

    # Also add EOF and TIMEOUT to the expected patterns to avoid the verbose
    # output of pexpect.expect when the expected patterns are not found
    patterns = [pexpect.EOF, pexpect.TIMEOUT] + accept + reject

    # Actually look for the expected patterns
    index = super().expect(patterns)

    # Handle EOF and TIMEOUT, then raise the corresponding exception
    if index == 0 or index == 1:
      self.print('error: expected output not found.')
      self.print('expected:', accept, reject)
      self.print('observed: %r' %(self.buffer[-self.str_last_chars:]))
    if index == 0:
      raise EOFError
    if index == 1:
      raise TimeoutError
    # Account for the prepended items in the patterns list
    index = index - 2

    # If the matching pattern belongs to the accepted list, return its index
    if index < len(accept):
      self.print('Accept pattern found:', accept[index])
      return index

    # Otherwise, the matching pattern belongs to the rejected list
    index = index - len(accept)
    if index >= valgrind_reject_index:
        self.print('Valgrind error detected.')
        raise MemoryError
    else:
        self.print('Reject pattern found:', reject[index])
        raise ValueError

  # Verify sanity of arguments to ulp tools
  def sanity(self, filename=Ellipsis, pid=Ellipsis):

    # Check if the process with PID exists
    if not pid == Ellipsis:
      if not psutil.pid_exists(pid):
        raise ValueError('Process ' + str(pid) + ' not found')

    # Check if the live patch file exists
    if not filename == Ellipsis and filename is not None:
      file = pathlib.Path(filename)
      if not file.is_file():
        raise FileNotFoundError('File ' + filename + ' not found')

  # Dump a compiled metadata file (.ulp) provided in metadata
  def show_metadata(self, metadata):
    # See if there is a .dsc file. On true, print it as well.
    suffix = metadata.rfind(".ulp")
    dsc = metadata[:suffix] + ".dsc"
    if os.path.isfile(dsc):
      self.print(dsc + " content:")
      dscf = open(dsc, 'r')
      content = dscf.read()
      dscf.close()
      self.print(content)

    # Now print the .ulp file
    command = [ulptool, "dump", metadata]
    try:
      self.print(metadata + ' content:')
      tool = subprocess.run(command, timeout=10)
    except subprocess.TimeoutExpired:
      self.print('ulp dump timed out.')
      raise


  # Apply a live patch to the spawned process. The path to the live patch
  # metadata must be passed through 'filename'. The remaining parameters, which
  # are optional, are the same that the Trigger tool provides (see its --help
  # output for more information).
  def livepatch(self, filename=None, timeout=10, retries=1,
                verbose=True, quiet=False, revert=False, revert_lib=None,
                sanity=True):

    # Check sanity of command-line arguments
    if sanity is True:
      self.sanity(pid=self.pid)
      self.sanity(filename=filename)

    # Build command-line from arguments
    command = [ulptool, "trigger", '-p', str(self.pid)]
    if revert is True:
      command.append("--revert")
    if revert_lib is not None:
      command.append("--revert-all")
      command.append(revert_lib)
    if filename is not None:
      command.append(filename)
      self.print('')
      self.show_metadata(filename)
    if verbose:
      command.append('-v')
    if quiet:
      command.append('-q')
    if retries > 1:
      command.append('-r')
      command.append(str(retries))

    # Apply the live patch and check for common errors
    try:
      self.print('Applying/reverting live patch.')
      tool = subprocess.run(command, timeout=timeout)
    except subprocess.TimeoutExpired:
      self.print('Live patching timed out.')
      raise

    self.print("---- Messages in libpulp.so ----")
    self.print(self.get_libpulp_messages())

    # The trigger tool returns 0 on success, so use check_returncode(),
    # which asserts that, and raises CalledProcessError otherwise.
    if sanity is True:
      tool.check_returncode()
    if revert == True:
      self.print('Live patch reverted successfully.')
    else:
      self.print('Live patch applied successfully.')

  # Check if a live patch is already applied. The path to the live patch
  # metadata must be passed through 'filename'. The remaining parameters, which
  # are optional, are the same that the Checker tool provides (see its --help
  # output for more information).
  def is_patch_applied(self, filename, verbose=True, quiet=False):

    # Check sanity of command-line arguments
    self.sanity(pid=self.pid)
    self.sanity(filename=filename)

    # Build command-line from arguments
    command = [ulptool, '-p', str(self.pid), "check",  filename]
    if verbose:
      command.append('-v')
    if quiet:
      command.append('-q')

    # Apply the live patch and check for common errors
    try:
      self.print('Checking live patch status.')
      tool = subprocess.run(command, timeout=10, stderr=subprocess.STDOUT)
    except subprocess.TimeoutExpired:
      self.print('Live patch status check timed out.')
      raise

    # On success, the checker tool returns either 0 or 1:
    #   1. If the given live patch has already been applied;
    #   0. If it has not.
    if tool.returncode == 0 or tool.returncode == 1:
      self.print('Live patch status check ended successfully. ', end='')
    if tool.returncode == 0:
      self.print('Status is not applied.')
      return False
    if tool.returncode == 1:
      self.print('Status is applied.')
      return True

    # Whereas on failure, the checker tool returns something different,
    # usually -1, so raise CalledProcessError.
    raise subprocess.CalledProcessError

  def is_so_loaded(self, fname_so):
    mapsf = open('/proc/' + str(self.pid) + '/maps', 'r')
    maps = mapsf.read()
    mapsf.close()

    if maps.find(fname_so) == -1:
      return False
    return True

  # Get libpulp messages, currently by calling ulp_messages and parsing
  # its stdout.
  def get_libpulp_messages(self):
    self.sanity(pid=self.pid)
    command = [ulptool, 'messages', '-p', str(self.pid)]

    try:
      self.print('Checking libpulp.so messages.')
      tool = subprocess.run(command, timeout=10, stdout=subprocess.PIPE)
    except:
      raise

    msgs = tool.stdout.decode()
    return str(msgs)
