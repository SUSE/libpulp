#!/bin/sh

CC="gcc"
BFD_DIR="./binutils/"
ULP_LD="${BFD_DIR}bin/ld"
LINKER="/lib64/ld-linux-x86-64.so.2"
LIB="/usr/lib64/"
LD="ld"

set -e

echo $'*** LIBPULP:'
echo $'** Cleaning up build dir'
cd build
rm -f *.o
rm -f *.so
rm -f *.ulp
cd ..

echo $'** Building libpulp'
./build-lib.sh

echo $'** Building libdummy'
pwd
${CC} -c ../src/libdummy/libdummy.c -o ./build/libdummy.o -Wall -fPIC
# weak is built just to show that modified binutils support weak symbols
${CC} -c ../src/libdummy/weak.c -o ./build/weak.o -Wall -fPIC
${ULP_LD} -shared -o build/libdummy.so build/libdummy.o build/weak.o build/trm.o -lc --build-id

echo $'\n** Adjusting .dynsym and .ulp'
./build/dynsym_gate build/libdummy.so

echo $'** Building examples'
${CC} -c ../src/ex_1/ex1.c -o ./build/ex1.o
${CC} -c ../src/ex_2/ex2.c -o ./build/ex2.o
${CC} -c ../src/ex_3/ex3.c -o ./build/ex3.o
${LD} -dynamic-linker ${LINKER} ${LIB}crt1.o ${LIB}crti.o ./build/ex1.o ${LIB}crtn.o -lc -ldl -ldummy -Lbuild --build-id -o ./build/ex1
${LD} -dynamic-linker ${LINKER} ${LIB}crt1.o ${LIB}crti.o ./build/ex2.o ${LIB}crtn.o -lc -ldl -lpthread -ldummy -Lbuild --build-id -o ./build/ex2
${LD} -dynamic-linker ${LINKER} ${LIB}crt1.o ${LIB}crti.o ./build/ex3.o ${LIB}crtn.o -lc -ldl -ldummy -Lbuild --build-id -o ./build/ex3

echo $'\n** For this example to work properly, make sure you copy libdummy.so to /usr/lib64'
echo $'** (the right path is critical to the example)'

echo $'\n** DONE'
