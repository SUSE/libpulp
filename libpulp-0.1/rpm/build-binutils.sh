#!/bin/sh

BFD_DIR="$(pwd)/binutils/"
NUMCORES="8"

set -e

# This compiles the entire binutils but only bfd is needed.
# TODO: fix this.
echo "** building modified binutils (bfd/ld)"
cd ../binutils-ulp/
./configure --prefix=$BFD_DIR
make clean
make -j${NUMCORES}
make install

