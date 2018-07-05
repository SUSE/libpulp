#!/bin/sh

CC="gcc"
BFD_DIR="/usr/ulp/binutils/"
LD="${BFD_DIR}bin/ld"
LINKER="/lib64/ld-linux-x86-64.so.2"
LIB="/usr/lib64/"

set -e

echo $'** Setting up environment'
if [ -d "./build" ]; then
    echo "  -- cleaning old build"
    rm -rf ./build
fi

mkdir ./build

echo $'\n** Building libpulp, packer, plt_swap, trigger and dump'
${CC} ../lib/ulp.c -c -o ./build/ulp.o -fPIC
${CC} ../lib/ulp_interface.S -c -o ./build/ulp_interface.o -fPIC
${CC} ./build/ulp.o ./build/ulp_interface.o -shared -o ./build/libpulp.so -fPIC -ldl -Wall
${CC} -c ../lib/trm.S -o ./build/trm.o -fPIC --shared
${CC} ../tools/packer/packer.c -o ./build/packer -lelf -Wall
${CC} ../tools/dynsym_gate/dynsym_gate.c -o ./build/dynsym_gate -lelf -Wall
${CC} ../tools/trigger/trigger.c -c -o ./build/trigger.o
${CC} ../tools/trigger/ptrace.c -c -o ./build/ptrace.o
${CC} ./build/trigger.o ./build/ptrace.o -o ./build/trigger -lelf -lbfd -lz -liberty -ldl -lpthread

echo $'\n** DONE'
