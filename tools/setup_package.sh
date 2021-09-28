#!/bin/bash

# Color special caracters.
GREEN='\033[1;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running bash
if [ -z "$BASH" ]; then
    echo "This script must be run with bash!"
    exit 1
fi

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


# Check if user have the necessary tools.
for tool in osc xpath cpio rpm2cpio xxd; do
  which $tool > /dev/null
  if [ $? -ne 0 ]; then
    fail "$tool not found, but is necessary by $0"
  fi
done

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

_TARGET_REPO="home:simotek:ulp"
__PACKAGE_NAME="openssl-1_1"
__LIB_NAME="libopenssl1_1"
__LIB_FILENAME="libcrypto.so.1.1"


__MULTIBUILD_FILE="_multibuild.template"

__DIST_NAME="openSUSE:Leap:15.2:Update"
# Build Target is Dist Name but with _ instead of :
__BUILD_TARGET=${__DIST_NAME//:/_}
# Valid choices openSUSE / SUSE - Used for SUSE:Maintenance:XXXXX etc
__PRODUCT="openSUSE"
# lp152 for Leap 15.2 for example
__PKG_SUFFIX="lp152"

if [[ -f "$_TARGET_REPO" ]]; then
  echo "$__MULTIBUILD_FILE exists and therefore won't be recreated"
  __SKIP_MULTIBUILD="1"
fi

if [[ -z $__SKIP_MULTIBUILD ]]; then
  echo "<multibuild>" >> $__MULTIBUILD_FILE
fi

__tmp_dir=$(mktemp -d -t ulp-XXXXXXXXXX)
mkdir -p "$__tmp_dir/$__PACKAGE_NAME-libs"

for __PKG in $(osc -A https://api.opensuse.org ls $__DIST_NAME | grep "$__PACKAGE_NAME."); do

  echo "### $__PKG ###"
  __INCIDENT=${__PKG#*.}
  # Get history from osc api
  # Parse XML for versrel
  # Strip versrel=
  # Strip Quotes
  # Example api Call osc api "https://api.opensuse.org/build/openSUSE:Maintenance:16863/openSUSE_Leap_15.2_Update/x86_64/openssl-1_1.openSUSE_Leap_15.2_Update/_history"
  __FULL_VERSION=$(osc api "https://api.opensuse.org/build/$__PRODUCT:Maintenance:$__INCIDENT/$__BUILD_TARGET/x86_64/$__PACKAGE_NAME.$__BUILD_TARGET/_history" |
                   xpath -q  -e "//entry/@versrel" | grep -o '".*"' | sed 's/"//g')
  __BUILD_COUNT=$(osc api "https://api.opensuse.org/build/$__PRODUCT:Maintenance:$__INCIDENT/$__BUILD_TARGET/x86_64/$__PACKAGE_NAME.$__BUILD_TARGET/_history" |
                  xpath -q  -e "//entry/@bcnt" | grep -o '".*"' | sed 's/"//g')
  __FULL_VERSION="$__FULL_VERSION.$__BUILD_COUNT"
  __BUILD_VERSION=${__FULL_VERSION#*-}

  __PKG_VERSION=${__FULL_VERSION/"-"/"-$__PKG_SUFFIX."}

  echo "Version: $__FULL_VERSION"

  __RPM_FILENAME="$__LIB_NAME-$__PKG_VERSION.x86_64.rpm"
  echo "wget -q -P \"$__tmp_dir/rpms\" \"https://download.opensuse.org/update/leap/15.2/oss/x86_64/$__RPM_FILENAME\""
  wget -q --show-progress -P "$__tmp_dir/rpms" "https://download.opensuse.org/update/leap/15.2/oss/x86_64/$__RPM_FILENAME"

  # Extract filename
  mkdir -p "$__tmp_dir/$__PACKAGE_NAME-libs/extract"
  pushd "$__tmp_dir/$__PACKAGE_NAME-libs/extract"
  rpm2cpio "$__tmp_dir/rpms/$__RPM_FILENAME" | cpio -idmv
  popd
  mkdir -p "$__tmp_dir/$__PACKAGE_NAME-libs/$__FULL_VERSION/usr/lib64/"

  cp "$__tmp_dir/$__PACKAGE_NAME-libs/extract/usr/lib64/$__LIB_FILENAME" "$__tmp_dir/$__PACKAGE_NAME-libs/$__FULL_VERSION/usr/lib64/$__LIB_FILENAME"
  rm -r "$__tmp_dir/$__PACKAGE_NAME-libs/extract"

  is_lib_livepatcheable "$__tmp_dir/$__PACKAGE_NAME-libs/$__FULL_VERSION/usr/lib64/$__LIB_FILENAME"
  if [ $? -ne 0 ]; then
    warn "library $__tmp_dir/$__PACKAGE_NAME-libs/$__FULL_VERSION/usr/lib64/$__LIB_FILENAME is not livepatchable: missing NOP prologue"
  fi
done

tar -caf "$__PACKAGE_NAME-libs.tar.xz" -C "$__tmp_dir/" "$__PACKAGE_NAME-libs"

rm -r "$__tmp_dir"
