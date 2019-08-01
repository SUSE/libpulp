#!/bin/sh

CC="/usr/ulp/gcc/bin/gcc"
BFD_DIR="/usr/ulp/binutils/"
ULP_LD="${BFD_DIR}bin/ld"
LIB="/usr/"
LINKER="/lib64/ld-linux-x86-64.so.2"
LD="ld"
NOP_LENGTH="24,22"
FPATCH="-fpatchable-function-entry=${NOP_LENGTH}"
NUMCORES=4

set -e

echo $'*** LIBPULP:'
echo $'** Cleaning up build dir'
mkdir build

echo $'** Building libfibo'
${CC} -c libfibo/libfibo.c -o ./build/libfibo.o -Wall -fPIC -fpatchable-function-entry=${NOP_LENGTH}
${CC} -c libfibo/trm.S -o ./build/trm.o -fPIC --shared

echo $'** Linking libfibo'
${ULP_LD} --shared -o build/libfibo.so build/libfibo.o build/trm.o -lc -L${LIB}/lib -L/usr/lib64 --build-id
#${ULP_LD} --dynamic-linker ${LINKER} -rpath /usr/ulp/glibc/lib -shared -o build/libfibo.so build/libfibo.o -lc -L${LIB}/lib -L/usr/lib64 --build-id
ulp_dynsym_gate build/libfibo.so

echo $'** Building examples'
${CC} -c ex_1/ex1.c -o ./build/ex1.o
${LD} --dynamic-linker ${LINKER} -rpath /usr/ulp/libfibo/ ${LIB}lib64/crt1.o ${LIB}lib64/crti.o ./build/ex1.o ${LIB}lib64/crtn.o -L${LIB}/lib -L/usr/lib64 -L./build -lc -ldl -lfibo --build-id -o ./build/ex1

echo $'\n** DONE'
