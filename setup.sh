#!/bin/sh
sudo rpm -e libdummy_livepatch-0.1-0.x86_64
sudo rpm -e libpulp-0.1-0.x86_64
sudo rpm -e dummyapp-0.1-0.x86_64
rpmbuild -bb libpulp.spec
sudo rpm -ivh rpmbuild/rpms/x86_64/libpulp-0.1-0.x86_64.rpm
sudo rpm -ivh rpmbuild/rpms/x86_64/dummyapp-0.1-0.x86_64.rpm
rpmbuild -bb livepatch.spec
#sudo rpm -ivh rpmbuild/rpms/x86_64/libdummy_livepatch-0.1-0.x86_64.rpm
