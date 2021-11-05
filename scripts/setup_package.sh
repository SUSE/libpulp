#!/bin/bash

# Include our common lib. Don't use source, as it requires bash.
. common_lib.sh

ULP_PACKAGE_NAME="openssl-1_1"
# Use when library package and base package name are different ie libopenssl1_1 openssl-1_1
ULP_LIB_NAME="libopenssl1_1"
ULP_LIB_FILENAME="libcrypto.so.1.1"

ULP_MULTIBUILD_FILE="_multibuild.template"

# Valid choices openSUSE / SUSE - Used for SUSE:Maintenance:XXXXX etc
ULP_PRODUCT="SUSE"

#ULP_DIST_NAME="SUSE:SLE-15-SP2"
ULP_DIST_NAME="SUSE:SLE-15-SP2"

# Comment out to disable debug prints
ULP_DEBUG="On"

# lp152 for Leap 15.2 for example - Not needed for SLE
#ULP_PKG_SUFFIX="lp152"

get_ga_version() {
  # Get history from osc api
  # Parse XML for versrel
  # Only keep the last entry - sometimes stuff is broken and built multiple times
  # Strip versrel=
  # Strip Quotes
  # Example api Call oosc api https://api.suse.de/build/SUSE:SLE-15-SP2:GA/standard/x86_64/openssl-1_1/_history

  local package_name=$1
  local dist_name=$2
  local api=$3

  debug "osc api $api/build/$dist_name:GA/standard/x86_64/$package_name/_history"
  local tmp_version=$(osc api "$api/build/$dist_name:GA/standard/x86_64/$package_name/_history" |
                   xpath -q  -e "//entry/@versrel" | tail -1 | grep -o '".*"' | sed 's/"//g')
  local build_count=$(osc api "$api/build/$dist_name:GA/standard/x86_64/$package_name/_history" |
                  xpath -q  -e "//entry/@bcnt" | tail -1 | grep -o '".*"' | sed 's/"//g')
  echo "$tmp_version.$build_count"
}

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
  # Note if you have the dist NFS mount wget could be replaced with cp

  local tmp_dir=$1
  local product=$2
  local rpm_filename=$3
  # Strip SUSE:
  local dist=${4#*:}
  local type=$5

  local dist_lower="${dist,,}"

  if [[ $type == "Update" ]]; then
    # TODO: Also fetch non download RPM's
    if [[ $product == "openSUSE" ]]; then
      debug "wget -q -P \"$tmp_dir/rpms\" \"https://download.opensuse.org/update/leap/$dist/oss/x86_64/$rpm_filename\""
      wget -q --show-progress -P "$tmp_dir/rpms" "https://download.opensuse.org/update/leap/$dist/oss/x86_64/$rpm_filename"
      local ret=$?
      if [[ $ret != 0 ]]; then
        fail "wget returned $ret downloading $rpm_filename failed"
      fi
    elif [[ $product == "SUSE" ]]; then
      # This one uses 15-SP2 rather then SLE-15-SP2
      debug "wget -q -P \"$tmp_dir/rpms\" \"http://download.suse.de/updates/SUSE/Updates/SLE-Module-Basesystem/${dist#*-}/x86_64/update/x86_64/$rpm_filename\""
      wget -q --show-progress -P "$tmp_dir/rpms" "http://download.suse.de/updates/SUSE/Updates/SLE-Module-Basesystem/${dist#*-}/x86_64/update/x86_64/$rpm_filename"
      local ret=$?
      if [[ $ret != 0 ]]; then
        fail "wget returned $ret downloading $rpm_filename failed"
      fi
    fi
  else
    if [[ $product == "openSUSE" ]]; then
      debug "wget -q -P \"$tmp_dir/rpms\" \"http://download.opensuse.org/distribution/leap/$dist/repo/oss/x86_64//$rpm_filename\""
      wget -q --show-progress -P "$tmp_dir/rpms" "http://download.opensuse.org/distribution/leap/$dist/repo/oss/x86_64/$rpm_filename"
      local ret=$?
      if [[ $ret != 0 ]]; then
        fail "wget returned $ret downloading $rpm_filename failed"
      fi
    elif [[ $product == "SUSE" ]]; then
      # Example http://download.suse.de/full/full-sle15-sp2-x86_64/allrpms/libopenssl1_1.rpm
      # For some reason we need sle15-sp2 rather then sle-15-sp2
      debug "wget -q -P \"$tmp_dir/rpms\" \"http://download.suse.de/full/full-${dist_lower/sle-/sle}-x86_64/allrpms/$rpm_filename\""
      wget -q --show-progress -P "$tmp_dir/rpms" "http://download.suse.de/full/full-${dist_lower/sle-/sle}-x86_64/allrpms/$rpm_filename"
      local ret=$?
      if [[ $ret != 0 ]]; then
        fail "wget returned $ret downloading $rpm_filename failed"
      fi
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

# Build Target is Dist Name but with _ instead of :
__BUILD_TARGET="${ULP_DIST_NAME//:/_}_Update"

if [[ $ULP_PRODUCT == "openSUSE" ]]; then
__API="https://api.opensuse.org"
elif [[ $ULP_PRODUCT == "SUSE" ]]; then
__API="https://api.suse.de"
else
fail "ULP_PRODUCT is not correctly defined must be SUSE or openSUSE"
fi

if [[ -f "$ULP_MULTIBUILD_FILE" ]]; then
  warn "$ULP_MULTIBUILD_FILE exists and therefore won't be recreated"
  __SKIP_MULTIBUILD="1"
fi

if [[ -z $__SKIP_MULTIBUILD ]]; then
  echo "<multibuild>" >> $ULP_MULTIBUILD_FILE
fi

__TMP_DIR=$(mktemp -d -t ulp-XXXXXXXXXX)
mkdir -p "$__TMP_DIR/$ULP_PACKAGE_NAME-libs"

__FULL_VERSION=$(get_ga_version $ULP_PACKAGE_NAME $ULP_DIST_NAME $__API)

info "GA Package"
info "Version: \"$__FULL_VERSION\""

# SLE Doesn't have version in the filename but openSUSE does here
if [[ $ULP_PRODUCT == "openSUSE" ]]; then
  __RPM_FILENAME=$(get_rpm_filename "$ULP_LIB_NAME" "$ULP_PKG_SUFFIX" "$__FULL_VERSION")
elif [[ $ULP_PRODUCT == "SUSE" ]]; then
  __RPM_FILENAME="$ULP_LIB_NAME.rpm"
fi
fetch_rpm "$__TMP_DIR" "$ULP_PRODUCT" "$__RPM_FILENAME" "$ULP_DIST_NAME"

extract_so "$__TMP_DIR" "$ULP_PACKAGE_NAME" "$__FULL_VERSION" "$ULP_LIB_FILENAME" "$ULP_LIB_NAME.rpm"

# Fetch from updates
for __PKG in $(osc -A $__API ls "$ULP_DIST_NAME:Update" | grep "$ULP_PACKAGE_NAME."); do

  info "### $__PKG ###"
  __INCIDENT=${__PKG#*.}

  __FULL_VERSION=$(get_update_version "$__INCIDENT" "$ULP_PACKAGE_NAME" "$ULP_PRODUCT" "$__API" "$__BUILD_TARGET")

  info "Version: \"$__FULL_VERSION\""

  __RPM_FILENAME=$(get_rpm_filename "$ULP_LIB_NAME" "$ULP_PKG_SUFFIX" "$__FULL_VERSION")

  fetch_rpm "$__TMP_DIR" "$ULP_PRODUCT" "$__RPM_FILENAME" "$ULP_DIST_NAME" "Update"

  if [[ ! -f "$__TMP_DIR/rpms/$__RPM_FILENAME" ]]; then
    fail "$__TMP_DIR/rpms/$__RPM_FILENAME was not downloaded correctly"
  fi

  extract_so "$__TMP_DIR" "$ULP_PACKAGE_NAME" "$__FULL_VERSION" "$ULP_LIB_FILENAME" "$__RPM_FILENAME"
done

tar -caf "$ULP_PACKAGE_NAME-libs.tar.xz" -C "$__TMP_DIR/" "$ULP_PACKAGE_NAME-libs"

ok "Succesfully created $ULP_PACKAGE_NAME-libs.tar.xz"

rm -r "$__TMP_DIR"
