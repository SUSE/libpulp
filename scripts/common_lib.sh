#!/bin/bash

# Check if running bash
if [ -z "$BASH" ]; then
    echo "This script must be run with bash!"
    exit 1
fi

# Check if user have the necessary tools.
for tool in osc xpath cpio rpm2cpio xxd; do
  which $tool > /dev/null
  if [ $? -ne 0 ]; then
    fail "$tool not found, but is necessary by $0"
  fi
done

# Color special caracters.
GREEN='\033[1;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
PURPLE='\033[1;35m'
NC='\033[0m' # No Color

ok () {
  echo -e "${GREEN}OK: $1${NC}\n"
}

warn() {
  echo -e "${YELLOW}WARNING: $1${NC}\n"
}

fail () {
  echo -e "${RED}ERROR: $1${NC}\n"
  exit 1
}

# Debug to stderr as some functions use stdout to return info
debug() {
  if [[ ! -z "$ULP_DEBUG" ]]; then
    echo -e "${BLUE}DEBUG: $1${NC}\n" 1>&2;
  fi
}

info () {
  echo -e "${PURPLE}$1${NC}\n"
}

is_lib_livepatcheable() {
  ULP_NOPS_LEN=16
  ULP_PRE_NOPS_LEN=14
  ULP_NOP_OPCODE=90

  local lib_path=$1
  local address_of_a_symbol=`objdump -T $lib_path | grep '\.text' | head -n 1 | awk '{ print $1 }'`

  if [ $? -ne 0 ]; then
    fail "Unable to find a symbol in $lib_path"
  fi

  # Convert hexadecimal address in decimal so we can do mathematical operations
  local addr_decimal=`printf "%llu" "0x$address_of_a_symbol"`
  if [ $addr_decimal -eq 0 ]; then
    fail "Symbol at address found is invalid: $address_of_a_symbol"
  fi

  local ulp_prologue_dec=`expr $addr_decimal - $ULP_PRE_NOPS_LEN`
  local ulp_prologue_addr=`printf "0x%lx" $ulp_prologue_dec`

  # Get bytes at target library. It should have $ULP_NOPS_LEN nops (0x90 on x86)
  local insns=`xxd -s $ulp_prologue_addr -l $ULP_PRE_NOPS_LEN -c $ULP_PRE_NOPS_LEN \
    -g $ULP_PRE_NOPS_LEN $lib_path | grep -oEi "($ULP_NOP_OPCODE){$ULP_PRE_NOPS_LEN}"`

  # If library is not livepatcheable, insns is empty.
  if [ -z "$insns" ]; then
    return 1
  fi

  return 0
}
