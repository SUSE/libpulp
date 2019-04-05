#!/bin/sh

# make sure we are in the right directory
RUN_DIR=$(basename $(pwd))

if [ $RUN_DIR == "scripts" ];
then
	cd ..
	RUN_DIR=$(basename $(pwd))
fi

if [ $RUN_DIR != "libpulp" ];
then
	echo "Please, run this from libpulp root directory"
	exit
fi

# remove old tar.bz2 files and recreate them
rm -f libdummy_livepatch-0.1.tar.bz2
rm -f libpulp-0.1.tar.bz2
tar cjvf libpulp-0.1.tar.bz2 libpulp-0.1
tar cjvf libdummy_livepatch-0.1.tar.bz2 libdummy_livepatch-0.1
