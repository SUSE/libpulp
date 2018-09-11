#!/bin/sh

CC="gcc"

set -e
echo $'*** LIBPULP:'
echo $'** Building livepatch for example'
mkdir ./build
${CC} ./src/patch/patch.c -shared -o ./build/patch1.so -fPIC -Wall

/usr/bin/ulp_packer ./src/patch/descr.txt /usr/lib64/libdummy.so
mv metadata.ulp build/metadata1.ulp

echo $'**Make sure libdummy.so is in /usr/lib64'
echo $'\n** DONE'
