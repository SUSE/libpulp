#!/usr/bin/env python3

import argparse
import subprocess

def find_offset(file, name):
  nm = subprocess.Popen(['nm', file], stdout=subprocess.PIPE,
                        encoding='utf-8')
  for entry in nm.stdout.readlines():
    split = entry.split(sep=' ')
    symbol = split[2].rstrip('\n')
    if symbol == name:
      return split[0]
  return

# This program takes two arguments, first the path to the input file, then the
# path to the output file. The input file is a live patch description template,
# where every line starting with '#' contains a local (not-exported) variable
# whose address in the target library (__TARGET_OFFSET__), as well as the
# address of its reference in the live patch (__PATCH_OFFSET__) must be
# determined.
parser = argparse.ArgumentParser()
parser.add_argument('ifile')
parser.add_argument('ofile')
args = parser.parse_args()

ifile = open(args.ifile, 'r')
ofile = open(args.ofile, 'w')

# The path to the patch file is always at the first line
patch = ifile.readline()
patch = patch.rstrip('\n')

# The path to the target library is always at the second line,
# which always starts with '@'
target = ifile.readline()
target = target.rstrip('\n')
target = target.lstrip('@')

# Rewind the input file
ifile.seek(0)

# Iterate over all lines of the input file
for line in ifile:

  # Lines starting with '#' contain local variables
  if line[0] == '#':

    # Parse the line
    split = line.lstrip('#')
    split = split.split(':')

    # Get the name of the local variable in the target library
    tname = split[0]

    # Get the name of the local variable reference in the live patch
    pname = split[1]

    # Search for the local variable in the target library
    toff = find_offset(target, tname)

    # Search for the local variable reference in the live patch
    poff = find_offset(patch, pname)

    # Replace offset template patterns with actual offsets
    line = line.replace('__TARGET_OFFSET__', toff)
    line = line.replace('__PATCH_OFFSET__', poff)

  # Write every line back to the output file
  ofile.write(line)

ifile.close()
ofile.close()
