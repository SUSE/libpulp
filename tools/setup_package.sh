#!/bin/bash

# Color special caracters.
GREEN='\033[1;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m' # No Color

# Comment out to disable debug prints
DEBUG="On"

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

# Debug to stderr as some functions use stdout to return info
debug() {
  if [[ ! -z "$DEBUG" ]]; then
    echo -e "${BLUE}DEBUG: $1${NC}\n" 1>&2;
  fi
}

# Check if user have the necessary tools.
for tool in osc xpath cpio rpm2cpio xxd; do
  which $tool > /dev/null
  if [ $? -ne 0 ]; then
    fail "$tool not found, but is necessary by $0"
  fi
done

get_update_version() {
  # Get history from osc api
  # Parse XML for versrel
  # Only keep the last entry - sometimes stuff is broken and built multiple times
  # Strip versrel=
  # Strip Quotes
  # Example api Call osc api "https://api.opensuse.org/build/openSUSE:Maintenance:16863/openSUSE_Leap_15.2_Update/x86_64/openssl-1_1.openSUSE_Leap_15.2_Update/_history"
  local incident=$1
  local package_name=$2
  local product=$3
  local api=$4
  local build_target=$5

  debug "osc api $api/build/$product:Maintenance:$incident/$build_target/x86_64/$package_name.$build_target/_history"
  local tmp_version=$(osc api "$api/build/$product:Maintenance:$incident/$build_target/x86_64/$package_name.$build_target/_history" |
                   xpath -q  -e "//entry/@versrel" | tail -1 | grep -o '".*"' | sed 's/"//g')
  local build_count=$(osc api "$api/build/$product:Maintenance:$incident/$build_target/x86_64/$package_name.$build_target/_history" |
                  xpath -q  -e "//entry/@bcnt" | tail -1 | grep -o '".*"' | sed 's/"//g')
  echo "$tmp_version.$build_count"
}

get_rpm_filename() {
  local lib_name=$1
  local pkg_suffix=$2
  local full_version=$3

  if [[ -n $pkg_suffix ]]; then
    echo "$lib_name-${full_version/"-"/"-$pkg_suffix."}.x86_64.rpm"
  else
    echo "$lib_name-$full_version.x86_64.rpm"
  fi
}

fetch_rpm() {
  local tmp_dir=$1
  local product=$2
  local rpm_filename=$3

  # TODO: Also fetch non download RPM's
  if [[ $product == "openSUSE" ]]; then
    debug "wget -q -P \"$tmp_dir/rpms\" \"https://download.opensuse.org/update/leap/15.2/oss/x86_64/$rpm_filename\""
    wget -q --show-progress -P "$tmp_dir/rpms" "https://download.opensuse.org/update/leap/15.2/oss/x86_64/$rpm_filename"
    local ret=$?
    if [[ $ret != 0 ]]; then
      error "wget returned $ret downloading $rpm_filename failed"
    fi

  elif [[ $product == "SUSE" ]]; then
    debug "wget -q -P \"$tmp_dir/rpms\" \"http://download.suse.de/updates/SUSE/Updates/SLE-Module-Basesystem/15-SP2/x86_64/update/x86_64/$rpm_filename\""
    wget -q --show-progress -P "$tmp_dir/rpms" "http://download.suse.de/updates/SUSE/Updates/SLE-Module-Basesystem/15-SP2/x86_64/update/x86_64/$rpm_filename"
    local ret=$?
    if [[ $ret != 0 ]]; then
      error "wget returned $ret downloading $rpm_filename failed"
    fi
  fi
}

extract_so() {
  local tmp_dir=$1
  local package_name=$2
  local full_version=$3
  local lib_filename=$4
  local rpm_filename=$5

  # Extract filename
  mkdir -p "$tmp_dir/$package_name-libs/extract"
  pushd "$tmp_dir/$package_name-libs/extract"
  rpm2cpio "$tmp_dir/rpms/$rpm_filename" | cpio -idmv
  popd
  mkdir -p "$tmp_dir/$package_name-libs/$full_version/usr/lib64/"

  cp "$tmp_dir/$package_name-libs/extract/usr/lib64/$lib_filename" "$tmp_dir/$package_name-libs/$full_version/usr/lib64/$lib_filename"
  rm -r "$tmp_dir/$package_name-libs/extract"

  is_lib_livepatcheable "$tmp_dir/$package_name-libs/$full_version/usr/lib64/$lib_filename"
  if [ $? -ne 0 ]; then
    warn "library $tmp_dir/$package_name-libs/$full_version/usr/lib64/$lib_filename is not livepatchable: missing NOP prologue"
  fi
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

_TARGET_REPO="home:simotek:ulp"
__PACKAGE_NAME="openssl-1_1"
__LIB_NAME="libopenssl1_1"
__LIB_FILENAME="libcrypto.so.1.1"


__MULTIBUILD_FILE="_multibuild.template"

#__DIST_NAME="openSUSE:Leap:15.2:Update"
__DIST_NAME="SUSE:SLE-15-SP2:Update"
# Build Target is Dist Name but with _ instead of :
__BUILD_TARGET=${__DIST_NAME//:/_}
# Valid choices openSUSE / SUSE - Used for SUSE:Maintenance:XXXXX etc
__PRODUCT="SUSE"

if [[ $__PRODUCT == "openSUSE" ]]; then
__API="https://api.opensuse.org"
elif [[ $__PRODUCT == "SUSE" ]]; then
__API="https://api.suse.de"
else
fail "__PRODUCT is not correctly defined must be SUSE or openSUSE"
fi

# lp152 for Leap 15.2 for example - Not needed for SLE
#__PKG_SUFFIX="lp152"

if [[ -f "$_TARGET_REPO" ]]; then
  echo "$__MULTIBUILD_FILE exists and therefore won't be recreated"
  __SKIP_MULTIBUILD="1"
fi

if [[ -z $__SKIP_MULTIBUILD ]]; then
  echo "<multibuild>" >> $__MULTIBUILD_FILE
fi

__TMP_DIR=$(mktemp -d -t ulp-XXXXXXXXXX)
mkdir -p "$__TMP_DIR/$__PACKAGE_NAME-libs"

for __PKG in $(osc -A $__API ls $__DIST_NAME | grep "$__PACKAGE_NAME."); do

  echo "### $__PKG ###"
  __INCIDENT=${__PKG#*.}

  __FULL_VERSION=$(get_update_version "$__INCIDENT" "$__PACKAGE_NAME" "$__PRODUCT" "$__API" "$__BUILD_TARGET")

  echo "Version: \"$__FULL_VERSION\""

  __RPM_FILENAME=$(get_rpm_filename "$__LIB_NAME" "$__PKG_SUFFIX" "$__FULL_VERSION")

  fetch_rpm $__TMP_DIR $__PRODUCT $__RPM_FILENAME

  if [[ ! -f "$__TMP_DIR/rpms/$__RPM_FILENAME" ]]; then
    fail "$__TMP_DIR/rpms/$__RPM_FILENAME was not downloaded correctly"
  fi

  extract_so "$__TMP_DIR" "$__PACKAGE_NAME" "$__FULL_VERSION" "$__LIB_FILENAME" "$__RPM_FILENAME"
done

tar -caf "$__PACKAGE_NAME-libs.tar.xz" -C "$__TMP_DIR/" "$__PACKAGE_NAME-libs"

rm -r "$__TMP_DIR"
