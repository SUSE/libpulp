#!/bin/sh
sudo rpm -e libdummy_livepatch-0.1-0.x86_64
sudo rpm -e libpulp-0.1-0.x86_64
sudo rpm -e dummyapp-0.1-0.x86_64
rpmbuild -bb libpulp.spec
sudo rpm -ivh rpmbuild/rpms/x86_64/libpulp-0.1-0.x86_64.rpm
sudo rpm -ivh rpmbuild/rpms/x86_64/dummyapp-0.1-0.x86_64.rpm
rpmbuild -bb livepatch.spec
#s/dummyapp1/dummyappX/ to test different apps
LD_PRELOAD=/usr/lib64/libpulp.so /usr/bin/dummyapp1 &
sleep 3
sudo rpm -ivh rpmbuild/rpms/x86_64/libdummy_livepatch-0.1-0.x86_64.rpm
sleep 3
sudo rpm -e libdummy_livepatch-0.1-0.x86_64.rpm
sleep 1
LD_PRELOAD=/usr/lib64/libpulp.so /usr/bin/dummyapp3 &
sudo rpm -ivh rpmbuild/rpms/x86_64/libdummy_livepatch-0.1-0.x86_64.rpm
sleep 5
killall dummyapp1
killall dummyapp3
sleep 2
