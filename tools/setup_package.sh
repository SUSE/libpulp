#!/bin/bash

# Requires osc commandline tool
#          xpath
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
  echo "$__MULTIBUILD_FILE exists won't recreate"
  __SKIP_MULTIBUILD="1"
fi

if [[ -z $__SKIP_MULTIBUILD ]]; then
  echo "<multibuild>" >> $__MULTIBUILD_FILE
fi

__tmp_dir=$(mktemp -d -t ulp-XXXXXXXXXX)
mkdir -p "$__tmp_dir/$__PACKAGE_NAME-libs"

for __PKG in $(osc ls $__DIST_NAME | grep "$__PACKAGE_NAME."); do

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
echo "wget -P \"$__tmp_dir/rpms\" \"https://download.opensuse.org/update/leap/15.2/oss/x86_64/$__RPM_FILENAME\""
wget -P "$__tmp_dir/rpms" "https://download.opensuse.org/update/leap/15.2/oss/x86_64/$__RPM_FILENAME"

# Extract filename
mkdir -p "$__tmp_dir/$__PACKAGE_NAME-libs/extract"
pushd "$__tmp_dir/$__PACKAGE_NAME-libs/extract"
rpm2cpio "$__tmp_dir/rpms/$__RPM_FILENAME" | cpio -idmv
popd
mkdir -p "$__tmp_dir/$__PACKAGE_NAME-libs/$__FULL_VERSION/usr/lib64/"
cp "$__tmp_dir/$__PACKAGE_NAME-libs/extract/usr/lib64/$__LIB_FILENAME" "$__tmp_dir/$__PACKAGE_NAME-libs/$__FULL_VERSION/usr/lib64/$__LIB_FILENAME"
rm -r "$__tmp_dir/$__PACKAGE_NAME-libs/extract"

done

tar -caf "$__PACKAGE_NAME-libs.tar.xz" -C "$__tmp_dir/" "$__PACKAGE_NAME-libs"

rm -r "$__tmp_dir"
