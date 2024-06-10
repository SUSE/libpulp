#!/bin/bash
#
#   libpulp - User-space Livepatching Library
#
#   Copyright (C) 2020-2023 SUSE Software Solutions GmbH
#
#   This file is part of libpulp.
#
#   libpulp is free software; you can redistribute it and/or
#   modify it under the terms of the GNU Lesser General Public
#   License as published by the Free Software Foundation; either
#   version 2.1 of the License, or (at your option) any later version.
#
#   libpulp is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#   Lesser General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with libpulp.  If not, see <http://www.gnu.org/licenses/>.

PROGNAME=`basename "$0"`

SLE_VERSION_REGEX="[0-9]{6}"
VERSION_REGEX="([0-9\.a-zA-Z]+-$SLE_VERSION_REGEX\.[0-9\.]+[0-9])"
PLATFORM=
PRODUCT=
URL=
PACKAGE=
NO_CLEANUP=0

# If this flag is enabled, then download of src packages will be blocked.
NO_SRC_DOWNLOAD=0

# If this flag is enabled, then download of ipa clones tarballs will be blocked.
NO_IPA_CLONES_DOWNLOAD=0

# If this flag is enabled, then download of debuginfo packages will be blocked.
NO_DEBUGINFO_DOWNLOAD=0

# Pushd and popd are not silent. Silence them.
pushd ()
{
  command pushd "$@" > /dev/null
}
popd ()
{
  command popd "$@" > /dev/null
}

set_url_platform()
{
  PLATFORM=$1
  PRODUCT=$2
  local element=$3

  URL="https://download.suse.de/download/ibs/SUSE:/SLE-$PLATFORM:/$PRODUCT/standard"

  if [ "$element" == "src" ]; then
    URL="$URL/src"
  elif [ "$element" != "ipa-clones" ]; then
    URL="$URL/x86_64"
  fi
}

web_get()
{
  echo downloading "$1"
  if [ -z "$2" ]; then
    wget -4 --show-progress --no-check-certificate "$1"
  else
    wget -4 --show-progress --no-check-certificate -O "$2" "$1"
  fi

  if [ $? -eq 4 ]; then
    echo Unable to download $1
    exit 1
  fi
}

get_version_from_package_name()
{
  local package=$1
  local version=$(echo "$1" | grep -Eo $VERSION_REGEX)

  echo $version
}

get_name_from_package_name()
{
  local package=$1
  IFS='-' tokens=( $package )

  echo ${tokens[0]}
}

get_sle_version_from_package_name()
{
  local package=$1
  # Declare a hash table mapping version number to a label used in
  # download.suse.de

  declare -A sle_hash=( ["150000"]="15"
                        ["150100"]="15-SP1"
                        ["150200"]="15-SP2"
                        ["150300"]="15-SP3"
                        ["150400"]="15-SP4"
                        ["150500"]="15-SP5")


  local version=$(echo "$1" | grep -Eo "($SLE_VERSION_REGEX)")

  local sle_version=${sle_hash[$version]}

  if [ "x$sle_version" = "x" ]; then
    "Unsupported SLE package version $version"
    exit 1
  fi

  echo $sle_version
}

extract_lib_package_names()
{
  local file=$1
  local lib_name=$2

  local interesting_lines=$(grep -Eo "$lib_name-$VERSION_REGEX\.x86_64.rpm\"" $1)
  local final=""

  for lib in ${interesting_lines}; do
    lib=${lib%?} # Remove last " from string.
    final="$final $lib"
  done

  echo $final
}

download_package_list()
{
  local url="$URL"
  local list_path=$1

  echo downloading package list: "$url"
  web_get "$url" "$list_path"
}

download_package()
{
  local package=$1
  local url="$URL/$package"

  web_get "$url"
}

parallel_download_packages()
{
  local packages="$*"

  local pids=""

  for package in $packages; do
    local url="$URL/$package"
    # If package already exists, do not bother downloading them again
    if [ ! -f "$package" ]; then
      echo "downloading from $url"
      wget -4 -q --show-progress --no-check-certificate "$url" &
      pid=$!
      pids="$pid $pids"
    else
      echo "Skipping $package because it is already downloaded"
    fi
  done

  # Wait download to finish
  if [ ! -z "$pids" ]; then
    for pid in $pids; do
      wait ${pid}
    done
  fi
}

# Get list of ipa-clones artifact from rpm packages.
get_list_of_ipa_clones()
{
  local packages="$*"
  local ipa_clones_list=""

  for package in $packages; do
    local package_name=$(get_name_from_package_name $package)
    local version=$(get_version_from_package_name $package)

    # libopenssl1_1 ipa-clones artifacts are named openssl.
    if [ "$package_name" = "libopenssl1_1" ]; then
      package_name="openssl"
    fi

    ipa_clones_list="$ipa_clones_list $package_name-livepatch-$version.x86_64.tar.xz"
  done

  echo $ipa_clones_list
}

# Get list of source packages from a list of main binary packages
get_list_of_src_packages()
{
  local packages="$*"
  local src_package_list=""

  for package in $packages; do
    local package_name=$(get_name_from_package_name $package)
    local version=$(get_version_from_package_name $package)

    # libopenssl1_1 src comes from openssl.
    if [ "$package_name" = "libopenssl1_1" ]; then
      package_name="openssl-1_1"
    fi

    src_package_list="$src_package_list $package_name-$version.src.rpm"
  done

  echo $src_package_list

}

# Get list of debuginfo packages
get_list_of_debuginfo_packages()
{
  local packages="$*"
  local src_package_list=""

  for package in $packages; do
    local package_name=$(get_name_from_package_name $package)
    local version=$(get_version_from_package_name $package)

    src_package_list="$src_package_list $package_name-debuginfo-$version.x86_64.rpm"
  done

  echo $src_package_list
}

download_debuginfo_packages()
{
  local packages=$(get_list_of_debuginfo_packages "$*")
  local old_url=$URL

  echo $packages

  set_url_platform $PLATFORM $PRODUCT "debuginfo"
  parallel_download_packages "$packages"
}

download_src_packages()
{
  local packages=$(get_list_of_src_packages "$*")
  local old_url=$URL

  set_url_platform $PLATFORM $PRODUCT "src"
  parallel_download_packages "$packages"
}

download_ipa_clones()
{
  # Set URL to IBS repository.
  local ipa_clones_list=$(get_list_of_ipa_clones "$*")
  local old_url=$URL

  local sle_ver=$(get_sle_version_from_package_name $1)

  set_url_platform $PLATFORM $PRODUCT "ipa-clones"
  parallel_download_packages "$ipa_clones_list"
}

extract_libs_from_package()
{
  local package=$1
  local version=$(get_version_from_package_name $package)
  local name=$(get_name_from_package_name $package)
  local ipa_clones=$(get_list_of_ipa_clones $package)
  local src_package=$(get_list_of_src_packages $package)
  local debuginfo_package=$(get_list_of_debuginfo_packages $package)

  mkdir -p $PLATFORM/$name/$version

  cp $package $PLATFORM/$name/$version/$package
  if [ $? -ne 0 ]; then
    echo "error: $package not downloaded."
    exit 1
  fi

  if [ $NO_SRC_DOWNLOAD -eq 0 ]; then
    cp $src_package $PLATFORM/$name/$version/$src_package
    if [ $? -ne 0 ]; then
      echo "error: $src_package not downloaded."
      exit 1
    fi
  fi

  if [ $NO_IPA_CLONES_DOWNLOAD -eq 0 ]; then
    cp $ipa_clones $PLATFORM/$name/$version/$ipa_clones
    if [ $? -ne 0 ]; then
      echo "error: $ipa_clones not downloaded."
      exit 1
    fi
  fi

  if [ $NO_DEBUGINFO_DOWNLOAD -eq 0 ]; then
    cp $debuginfo_package $PLATFORM/$name/$version/$debuginfo_package
    if [ $? -ne 0 ]; then
      echo "error: $debuginfo not downloaded."
      exit 1
    fi
  fi

  cd $PLATFORM/$name/$version
    mkdir -p binaries
    cd binaries
      if [ -f ../$package ]; then
        rpm2cpio ../$package | cpio -idm --quiet
      fi
    cd ..

    mkdir -p src
    cd src
      if [ -f ../$src_package ]; then
        rpm2cpio ../$src_package | cpio -idm --quiet
        tar xf $(ls | grep -E "(\.tar\.xz$|\.tar\.gz$)")
      fi
    cd ..

    mkdir -p debuginfo
    cd debuginfo
      if [ -f ../$debuginfo_package ]; then
        echo "Extracting $debuginfo_package"
        rpm2cpio ../$debuginfo_package | cpio -idm --quiet
      fi
    cd ..

    # Extract tar file and get rid of the version directory.
    if [ -f $ipa_clones ]; then
      echo "Extracting IPA clones package $ipa_clones"
      local extracted_tar_dir=$(tar tf $ipa_clones | sed -e 's@/.*@@' | uniq)
      tar -xf $ipa_clones
      mv $extracted_tar_dir/* ipa-clones
      rm -rf $extracted_tar_dir
    fi

    # delete anything we don't need.
    rm -f *.rpm *.tar.xz
  cd ../../../
}

# List of .debug files in folder.  Stored here for cache reasons.
_LIST_OF_DEBUG=""

match_so_to_debuginfo()
{
  local so=$1
  local base_so=$(basename $so)

  local list_of_debug=$(echo $_LIST_OF_DEBUG | xargs -n1 | grep -E "$base_so.*\.debug$")

  let num=0

  # Count how many files we got.
  for dbg in $list_of_debug; do
    let "num=num+1"
  done

  # Assert that we got only one file
  if [ $num -ne 1 ]; then
    echo "Expected only 1 file matching $base_so, got $num: $list_of_debug" > /dev/stderr
    exit 1
  fi

  # Return the file we got.
  echo $list_of_debug
}

dump_interesting_info_from_elfs()
{
  pushd $1
  local list_of_sos=$(find . | grep -E ".*\.so[\.0-9]*$")

  # Populate cache of list of .debug
  _LIST_OF_DEBUG=$(find . -name "*.debug")

  # Iterate on every so in the folder.
  for so in $list_of_sos; do
    if [ $NO_DEBUGINFO_DOWNLOAD -eq 0 ]; then
      # Get the debuginfo that matches this library.
      local debug=$(match_so_to_debuginfo $so)

      if [ "$debug" == "" ]; then
        exit 1
      fi

      # Run the ulp extract command on both the library and debuginfo.
      echo ulp extract $so -d $debug -o $so.json
      ulp extract $so -d $debug -o $so.json
    else
      # Run the ulp extract command only on the library.
      echo ulp extract $so -o $so.json
      ulp extract $so -o $so.json
    fi
  done

  # Delete all .so we don't need.
  for so in $list_of_sos; do
    rm -f $so
  done

  # Delete all .debug we we don't need.
  for debug in $_LIST_OF_DEBUG; do
    rm -f $debug
  done

  # Delete empty directories left.
  find . -type d -empty -delete

  # Invalidate the cache.
  _LIST_OF_DEBUG=""

  popd
}

dump_interesting_info_from_elfs_in_lib()
{
  local platform=$1

  # Enter in platform folder
  pushd $platform

  # Iterate on every version
  for dir in $(ls); do
    dump_interesting_info_from_elfs $dir
  done
  popd

}

sanitize_platform()
{
  local platforms="15-SP3 15-SP4 15-SP5"

  for platform in ${platforms}; do
    if [ "$PLATFORM" = "$platform" ]; then
      # Supported platform found.
      return 0
    fi
  done

  echo "Unsupported platform $PLATFORM"
  exit 1
}

sanitize_package()
{
  local packages="glibc libopenssl1_1"

  if [ "x$PACKAGE" = "x" ]; then
    echo "You must pass a --package=<PACKAGE> parameter!"
    exit 1
  fi

  for package in ${packages}; do
    if [ "$PACKAGE" = "$package" ]; then
      # Supported package found.
      return 0
    fi
  done

  echo "Unsupported package $PACKAGE"
  exit 1
}

print_help_message()
{
  echo "SUSE Linux Enterprise package download script"
  echo "Author: Giuliano Belinassi (gbelinassi@suse.de)"
  echo ""
  echo "Usage: $PROGNAME <switches>"
  echo "where <switches>"
  echo "  --platform=PLATFORM            SLE version (ex 15-SP4)."
  echo "  --package=PACKAGE              Package name to download (ex glibc)."
  echo "  --no-src-download              Do not download the src package."
  echo "  --no-ipa-clones-download       Do not download the ipa-clones tarballs."
  echo "  --no-cleanup                   Do not cleanup downloaded .rpm files."
  echo ""
  echo "supported <library> so far are 'glibc' and 'libopenssl1_1'"
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
      --platform=*)
        PLATFORM="${i#*=}"
        shift
        ;;
      --package=*)
        PACKAGE="${i#*=}"
        shift
        ;;
      --no-cleanup)
        NO_CLEANUP=1
        shift
        ;;
      --no-src-download)
        NO_SRC_DOWNLOAD=1
        shift
        ;;
      --no-ipa-clones-download)
        NO_IPA_CLONES_DOWNLOAD=1
        shift
        ;;
      --no-debuginfo-download)
        NO_DEBUGINFO_DOWNLOAD=1
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

  # Do some sanity checking
  sanitize_platform
  sanitize_package

  # Set platform globally
  set_url_platform "$PLATFORM" "GA"
}

main()
{
  parse_program_argv $*

  # Clean the directory
  rm -rf $PLATFORM

  local all_names=""
  local products="GA Update"

  for product in GA Update; do
    # Set platform globally
    set_url_platform "$PLATFORM" $product

    download_package_list "/tmp/suse_package_list.html"
    local names=$(extract_lib_package_names "/tmp/suse_package_list.html" $PACKAGE)

    # Clean the directory
    rm -rf $PLATFORM

    parallel_download_packages "$names"

    if [ $NO_SRC_DOWNLOAD -eq 0 ]; then
      download_src_packages "$names"
    fi
    if [ $NO_IPA_CLONES_DOWNLOAD -eq 0 ]; then
      download_ipa_clones "$names"
    fi
    if [ $NO_DEBUGINFO_DOWNLOAD -eq 0 ]; then
      download_debuginfo_packages "$names"
    fi

    all_names="$all_names $names"
  done

  for package in $all_names; do
    extract_libs_from_package "$package"
  done

  dump_interesting_info_from_elfs_in_lib $PLATFORM/$PACKAGE

  # Delete all packages to cleanup.
  if [ $NO_CLEANUP -ne 1 ]; then
    rm -f *.rpm *tar.xz
  fi
  echo "Done."
}

main $*
