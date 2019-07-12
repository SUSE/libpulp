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

# uninstal rpms, for when retrying
sudo rpm -e libdummy_livepatch_1-0.1-0.x86_64
sudo rpm -e libdummy_livepatch_2-0.1-0.x86_64

# build and install libpulp and the dummy example
rpmbuild -bb libdummy_livepatch_1.spec
rpmbuild -bb libdummy_livepatch_2.spec
