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
sudo rpm -e libdummy_livepatch-0.1-0.x86_64

# run example
# s/dummyapp1/dummyappX/ to test different apps
LD_PRELOAD=/usr/lib64/libpulp.so /usr/bin/dummyapp1 &
sleep 3
#sudo rpm -ivh rpmbuild/rpms/x86_64/libdummy_livepatch-0.1-0.x86_64.rpm
killall dummyapp1
#killall dummyapp3
sleep 2
