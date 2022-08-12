#!/bin/bash

PROGNAME=`basename "$0"`

# Script to extract a function from a project.

# Path of extracted packages:
PACKAGE_PATH=

# Function to extract
FUNCTION=

# Compiled binary. Can be a .so library or the program itself that has the
# symbol of interest.
BINARY=

# Project to extract from
PACKAGE_PATH=

OUTPUT=

IPA_CLONE=

# Path to CCP-POL scripts
P="$HOME/projects/kgr/scripts/ccp-pol"

# Path to compiled KLP-CCP
CCP="$HOME/projects/kgr/ccp/build/klp-ccp --pol-cmd-may-include-header=$P/kgr-ccp-pol-may-include-header.sh --pol-cmd-can-externalize-fun=$P/kgr-ccp-pol-can-externalize-fun.sh --pol-cmd-shall-externalize-fun=$P/kgr-ccp-pol-shall-externalize-fun.sh --pol-cmd-shall-externalize-obj=$P/kgr-ccp-pol-shall-externalize-obj.sh --pol-cmd-modify-externalized-sym=$P/kgr-ccp-pol-modify-externalized-sym.sh --pol-cmd-modify-patched-fun-sym=$P/kgr-ccp-pol-modify-patched-sym.sh --pol-cmd-rename-rewritten-fun=$P/kgr-ccp-pol-rename-rewritten-fun.sh"

CCP_CFLAGS=

set_project_cflags()
{
  # Get which project we are analyzing.
  local proj=$(echo $PACKAGE_PATH | grep -Eo "glibc|libopenssl1_1;")

  if [ $proj = "libopenssl1_1" ]; then

    local include_folder="-I$PACKAGE_PATH/src/openssl-1.1.1l/include
                          -I$PACKAGE_PATH/src/openssl-1.1.1l/"

    CCP_CFLAGS="-I/usr/include/
                -I/usr/include/bits/types/
                -I/usr/lib64/gcc/x86_64-suse-linux/7/include/
                -I/usr/lib64/gcc/x86_64-suse-linux/7/include-fixed
                -Icrypto/include
                -Iinclude
                -I/usr/local/include
                $include_folder
                -fPIC
                -pthread
                -m64
                -Wa,--noexecstack
                -Wall
                -O3
                -O2
                -Wall
                -fstack-protector-strong
                -funwind-tables
                -fasynchronous-unwind-tables
                -fstack-clash-protection
                -Werror=return-type
                -flto=auto
                -g
                -fpatchable-function-entry=16,14
                -fdump-ipa-clones
                -g3
                -Wa,--noexecstack
                -fno-common
                -Wall
                -DOPENSSL_USE_NODELETE
                -DL_ENDIAN
                -DOPENSSL_PIC
                -DOPENSSL_CPUID_OBJ
                -DOPENSSL_IA32_SSE2
                -DOPENSSL_BN_ASM_MONT
                -DOPENSSL_BN_ASM_MONT5
                -DOPENSSL_BN_ASM_GF2m
                -DSHA1_ASM
                -DSHA256_ASM
                -DSHA512_ASM
                -DKECCAK1600_ASM
                -DRC4_ASM
                -DMD5_ASM
                -DVPAES_ASM
                -DGHASH_ASM
                -DECP_NISTZ256_ASM
                -DX25519_ASM
                -DPOLY1305_ASM
                -DOPENSSLDIR="\"/etc/ssl\""
                -DENGINESDIR="\"/usr/lib64/engines-1.1\""
                -DNDEBUG
                -D_FORTIFY_SOURCE=2
                -DTERMIO
                -DPURIFY
                -D_GNU_SOURCE
                -DOPENSSL_NO_BUF_FREELISTS
                -D__THROW
                -MMD
                -MF ssl/s3_lib.d.tmp
                -MT $SOURCE
                -c
                -o ssl/s3_lib.o"

  elif [ $proj = "glibc" ]; then

    local glibc_ver="glibc-2.31"
    local src_path="$PACKAGE_PATH/src/$glibc_ver"

    local include_folder="
                -I$src_path/include
                -I$src_path/build/iconv
                -I$src_path/build
                -I$src_path/sysdeps/unix/sysv/linux/x86_64/64
                -I$src_path/sysdeps/unix/sysv/linux/x86/include
                -I$src_path/sysdeps/unix/sysv/linux/x86
                -I$src_path/sysdeps/x86/nptl
                -I$src_path/sysdeps/unix/sysv/linux/wordsize-64
                -I$src_path/sysdeps/x86_64/nptl
                -I$src_path/sysdeps/unix/sysv/linux/include
                -I$src_path/sysdeps/unix/sysv/linux
                -I$src_path/sysdeps/nptl
                -I$src_path/sysdeps/pthread
                -I$src_path/sysdeps/gnu
                -I$src_path/sysdeps/unix/inet
                -I$src_path/sysdeps/unix/sysv
                -I$src_path/sysdeps/unix/x86_64
                -I$src_path/sysdeps/unix
                -I$src_path/sysdeps/posix
                -I$src_path/sysdeps/x86_64/64
                -I$src_path/sysdeps/x86_64/fpu/multiarch
                -I$src_path/sysdeps/x86_64/fpu
                -I$src_path/sysdeps/x86/fpu/include
                -I$src_path/sysdeps/x86/fpu
                -I$src_path/sysdeps/x86_64/multiarch
                -I$src_path/sysdeps/x86_64
                -I$src_path/sysdeps/x86
                -I$src_path/sysdeps/ieee754/float128
                -I$src_path/sysdeps/ieee754/ldbl-96/include
                -I$src_path/sysdeps/ieee754/ldbl-96
                -I$src_path/sysdeps/ieee754/dbl-64/wordsize-64
                -I$src_path/sysdeps/ieee754/dbl-64
                -I$src_path/sysdeps/ieee754/flt-32
                -I$src_path/sysdeps/wordsize-64
                -I$src_path/sysdeps/ieee754
                -I$src_path/sysdeps/generic
                -I$src_path/sysdeps/unix/sysv/linux/x86_64
                -I$src_path
                -I$src_path/libio
                -I$src_path/build
                -I/usr/include/
                -I/usr/include/bits/types/
                -I/usr/lib64/gcc/x86_64-suse-linux/7/include/
                -I/usr/lib64/gcc/x86_64-suse-linux/7/include-fixed
                -include $src_path/build/libc-modules.h
                -include $src_path/include/libc-symbols.h"

    CCP_CFLAGS="-c -std=gnu11 -g -O2 -Wall
                -Wwrite-strings -Wundef -Werror
                -fmerge-all-constants -frounding-math
                -fno-stack-protector -Wstrict-prototypes
                -Wold-style-definition -fmath-errno
                -ftls-model=initial-exec
                $include_folder
                -D_LIBC_REENTRANT
                -DMODULE_NAME=libc
                -DTOP_NAMESPACE=glibc
                -o /home/giulianob/projects/libpulp/libpulp/scripts/15-SP4/glibc/2.31-150300.26.5/src/glibc-2.31/build/iconv/iconv_open.o
                -MD -MP
                -MF /home/giulianob/projects/libpulp/libpulp/scripts/15-SP4/glibc/2.31-150300.26.5/src/glibc-2.31/build/iconv/iconv_open.o.dt
                -MT /home/giulianob/projects/libpulp/libpulp/scripts/15-SP4/glibc/2.31-150300.26.5/src/glibc-2.31/build/iconv/iconv_open.o"

  else
    echo "Unsupported project"
    exit 1
  fi
}

# Set the KCP variables used by the policy scripts.
set_kcp_variables()
{
  export KCP_READELF=readelf
  export KCP_RENAME_PREFIX=klp
  export KCP_WORK_DIR=/tmp/kcp
  export KCP_KBUILD_SDIR=$PACKAGE_PATH
  export KCP_KBUILD_ODIR=$PACKAGE_PATH
  export KCP_PATCHED_OBJ=$PACKAGE_PATH/$BINARY
  export KCP_UNPATCHED_OBJ=$PACKAGE_PATH/$BINARY
  export KCP_IPA_CLONES_DUMP=$PACKAGE_PATH/$IPA_CLONE

  # _Pragma is used on glibc source to define weak aliases to symbols.
  # KLP-CCP doesn't implement that and probably never will.
  export KCP_EXT_BLACKLIST=weak_extern,_Static_assert
}

do_extract_function()
{
  local target_function=$FUNCTION
  local compiler_version="x86_64-gcc-9.1.0"
  local output="/tmp/lp.c"
  pushd $PACKAGE_PATH
  echo $KCP_PATCHED_OBJ

  set -o xtrace
  $CCP --compiler=$compiler_version \
       -i $FUNCTION \
       -o "$OUTPUT" \
       -- $CCP_CFLAGS $PACKAGE_PATH/$SOURCE
  set +o xtrace
  popd
}

print_help_message()
{
  echo "Extract function from project and its dependencies."
  echo "Author: Giuliano Belinassi (gbelinassi@suse.de)"
  echo "Based on klp-ccp"
  echo ""
  echo "Usage: $PROGNAME <switches>"
  echo "where <switches>"
  echo "  --function=FUNCTION            Function to extract."
  echo "  --package=PATH_TO_PROJECT      Path to project."
  echo "  --binary=PATH_TO_BINARY        Path to final .so file."
  echo "  --source=PATH_TO_SOURCE        Path to .c file containing FUNCTION."
  echo "  --output=PATH_TO_GENERATED_C   Path to output .c file."
  echo ""
  echo "Example: "
  echo "  ./extract_function.sh --function="SSL_load_client_CA_file" --package=15-SP4/libopenssl1_1/1.1.1l-150400.7.7.1 --binary="binaries/usr/lib64/libssl.so.1.1" --source="src/openssl-1.1.1l/ssl/ssl_cert.c" --ipa-clone=ipa-clones/ssl/ssl_cert.c.000i.ipa-clones --output=/tmp/lp.c"
}

sanitize_arguments()
{
  if [ ! -f $PACKAGE_PATH/$SOURCE ]; then
    echo "ERROR: Source file $PACKAGE_PATH/$SOURCE" does not exist.
    exit 1
  fi
#
#  if [ ! -f $PACKAGE_PATH/$IPA_CLONE ]; then
#    echo "ERROR: ipa-clone $PACKAGE_PATH/$IPA_CLONE" does not exist.
#    exit 1
#  fi
#
}

parse_program_argv()
{
  # If user didn't provide any arugment, then bails out with a help message.
  if [[ -z "$@" ]]; then
    print_help_message
    exit 0
  fi

  # Parse arguments provided by user.
  for i in "$@"; do
    case $i in
      --package=*)
        PACKAGE_PATH=$(realpath "${i#*=}")
        shift
        ;;
      --function=*)
        FUNCTION="${i#*=}"
        shift
        ;;
      --binary=*)
        BINARY="${i#*=}"
        shift
        ;;
      --source=*)
        SOURCE="${i#*=}"
        shift
        ;;
      --ipa-clone=*)
        IPA_CLONE="${i#*=}"
        shift
        ;;
      --output=*)
        OUTPUT="${i#*=}"
        shift
        ;;
      --help)
        print_help_message
        exit 0
        shift
        ;;
      -*|--*)
        echo "Unknown option $i"
        echo ""
        print_help_message

        exit 1
        ;;
      *)
        ;;
    esac
  done

  sanitize_arguments
}

main()
{
  parse_program_argv $*

  set_kcp_variables
  set_project_cflags

  do_extract_function
}

main $*
