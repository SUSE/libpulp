#!/bin/sh

CC="/usr/ulp/gcc/bin/gcc"
BFD_DIR="/usr/ulp/binutils/"
ULP_LD="${BFD_DIR}bin/ld"
LIB="/usr/"
LINKER="/lib64/ld-linux-x86-64.so.2"
LD="ld"
NOP_LENGTH="35,33"
FPATCH="-fpatchable-function-entry=${NOP_LENGTH}"
NUMCORES=4

set -e

echo $'*** LIBPULP:'
echo $'** Cleaning up build dir'
mkdir build

echo $'** Building libdummy'
${CC} -c libdummy/libdummy.c -o ./build/libdummy.o -Wall -fPIC -fpatchable-function-entry=${NOP_LENGTH}
# weak is built just to show that modified binutils support weak symbols
${CC} -c libdummy/weak.c -o ./build/weak.o -Wall -fPIC -fpatchable-function-entry=${NOP_LENGTH}
${CC} -c libdummy/trm.S -o ./build/trm.o -fPIC --shared

echo $'** Linking libdummy'
${ULP_LD} -shared -o build/libdummy.so build/libdummy.o build/weak.o build/trm.o -lc --build-id
ulp_dynsym_gate build/libdummy.so

echo $'** Building examples'
${CC} -c ex_1/ex1.c -o ./build/ex1.o
${CC} -c ex_2/ex2.c -o ./build/ex2.o
${CC} -c ex_3/ex3.c -o ./build/ex3.o
${LD} --dynamic-linker /lib64/ld-linux-x86-64.so.2 ${LIB}lib64/crt1.o ${LIB}lib64/crti.o ./build/ex1.o ${LIB}lib64/crtn.o -L${LIB}/lib -L/usr/lib64 -L./build -lc -ldl -ldummy --build-id -o ./build/ex1

${LD} --dynamic-linker /lib64/ld-linux-x86-64.so.2 ${LIB}lib64/crt1.o ${LIB}lib64/crti.o ./build/ex2.o ${LIB}lib64/crtn.o -L${LIB}/lib -L{LIB}/lib64 -L/usr/lib64 -L./build -lc -ldl -ldummy -lpthread --build-id -o ./build/ex2

${LD} --dynamic-linker /lib64/ld-linux-x86-64.so.2 ${LIB}lib64/crt1.o ${LIB}lib64/crti.o ./build/ex3.o ${LIB}lib64/crtn.o -L${LIB}/lib -L/usr/lib64 -L./build -lc -ldl -ldummy --build-id -o ./build/ex3

echo $'\n** DONE'
