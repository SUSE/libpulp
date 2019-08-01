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

# remove all packages
sudo rpm -e libdummy_livepatch-0.1-0.x86_64
sudo rpm -e libpulp-0.1-0.x86_64
sudo rpm -e dummyapp-0.1-0.x86_64
sudo rpm -e libdummy-0.1-0.x86_64

./scripts/build_libpulp.sh
./scripts/build_libdummy.sh
./scripts/build_libfibo.sh
./scripts/build_lp_libdummy.sh
