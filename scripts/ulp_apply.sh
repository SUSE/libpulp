#!/bin/bash

# Find the path to current script
CURR_SCRIPT=`readlink -f "$0"`
CURR_SCRIPT_PATH=`dirname $CURR_SCRIPT`

# Include our common lib
. $CURR_SCRIPT_PATH/common_lib.sh

# Usage: ./ulp_apply "/usr/lib64/libcrypto.so.1.1" "/usr/lib64/openssl-1_1-livepatches/libcrypto_livepatch1.ulp"

UPDATE_LIB=$1

# For each process
#  Check if lib we want to update is loaded and that libpulp is loaded
#  Todo: check for applied patch and revert - this is being done inside ulp trigger
#  Call ulp_buildid to get NT_GNU_BUILDID
#  Check BUILD_ID against each .ulp file, if found apply the live patch.

PULP_LIB="libpulp.so"
UPDATE_LIB=$1
ULP_FILES_PATH=$2
patched_count=0

sleep 0.5

for d in /proc/[0-9]*/ ; do
    PID=${d:6:-1}
    NEEDS_PATCH=$(find "$d/maps" -type f  -exec grep -q "$UPDATE_LIB" {} \; -exec grep -l "$PULP_LIB" {} \;)
    if [[ $NEEDS_PATCH ]]; then
      BUILD_ID=$(ulp patches -b -p $PID | grep $UPDATE_LIB | grep -oEi '([0-9a-f]){40}')
      debug "Detected running process: $PID; $UPDATE_LIB buildid: $BUILD_ID"

      for ulp_file in $ULP_FILES_PATH/*.ulp ; do
        FILE_BUILD_ID=$(ulp dump -b $ulp_file | sed 's/ //g')
        debug "Checking file: $ulp_file..."

        debug "FILE_BUILD_ID: $FILE_BUILD_ID"

        if [ -z $FILE_BUILD_ID ]; then
          fail "FATAL ERROR: ulp patch without build id: $ulp_file"
        fi

        if [[ "$BUILD_ID" == "$FILE_BUILD_ID" ]] ; then
          echo "Updating $PID"
          ulp dump $ulp_file
          debug ">> about to trigger..."
          debug "ulp trigger -v --revert-all=$UPDATE_LIB -p $PID $ulp_file"
          ulp trigger -v --revert-all=$UPDATE_LIB -p $PID $ulp_file
          patched_count=$(expr $patched_count + 1)
        fi
      done
    fi
done
ok "Patched a total of $patched_count processes."
