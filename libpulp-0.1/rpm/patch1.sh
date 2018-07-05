#!/bin/sh

LIBNAME="libdummy"

function patch_me
{
    echo $1
    /usr/bin/ulp_trigger $1 /tmp/metadata1.ulp
}

function check_permissions
{
    echo "check permissions"
}

check_permissions

cd /proc
for D in *;
do
    if [ -d ${D} ];
    then
	if [[ ${D} =~ [0-9] ]];
	then
	    pmap ${D} | grep -q ${LIBNAME}
	    if [ $? = 0 ];
	    then
		patch_me ${D}
	    fi
	fi
    fi
done
