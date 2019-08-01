#!/bin/sh

CC="gcc"

set -e
echo $'*** LIBPULP:'
echo $'** Building livepatch for example'
mkdir ./build
${CC} ./src/patch/patch.c -shared -o ./build/patch1.so -fPIC -Wall

/usr/bin/ulp_packer ./src/patch/descr.txt /usr/ulp/libfibo/libfibo.so
/usr/bin/ulp_reverse metadata.ulp
mv metadata.ulp build/metadata1.ulp
mv reverse.ulp build/reverse1.ulp

echo $'\n** DONE'
