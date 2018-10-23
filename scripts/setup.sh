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

# uninstall old packages, for when retrying
sudo rpm -e libdummy_livepatch-0.1-0.x86_64
sudo rpm -e libpulp-0.1-0.x86_64
sudo rpm -e dummyapp-0.1-0.x86_64

# build and install libpulp and examples
rpmbuild -bb libpulp.spec
sudo rpm -ivh rpmbuild/rpms/x86_64/libpulp-0.1-0.x86_64.rpm
sudo rpm -ivh rpmbuild/rpms/x86_64/dummyapp-0.1-0.x86_64.rpm
rpmbuild -bb livepatch.spec
#sudo rpm -ivh rpmbuild/rpms/x86_64/libdummy_livepatch-0.1-0.x86_64.rpm
