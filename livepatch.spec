#
# spec file for package libpulp
#
# Copyright (c) 2018 SUSE LINUX Products GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#

Name:           libdummy_livepatch
Version:	0.1
Release:	0
License:	SUSE-GPL-2.0
Summary:	Livepatch for libdummy
Source0:	%{name}-%{version}.tar.bz2

%define topdir %(echo $PWD)/rpmbuild
%define _builddir %{topdir}/build
%define _rpmdir %{topdir}/rpms
%define _sourcedir %(echo $PWD)
%define _specdir %(echo $PWD)
%define _srcrpmdir %{topdir}/rpms

# tricky part: we need to build using libdummy 0.1 binaries, but before
# installing, we need to make sure that these binaries are up to date
BuildRequires:	dummyapp = 0.1
BuildRequires:	libpulp
Requires:	libpulp

%description
This package provides a livepatch for libdummy.

%prep
%setup -q -n libdummy_livepatch-%{version}

%build
./build-livepatch.sh

%install
mkdir -p %{buildroot}/tmp/
mv ./build/patch1.so %{buildroot}/tmp/patch1.so
mv ./build/metadata1.ulp %{buildroot}/tmp/metadata1.ulp
mv ./patch1.sh %{buildroot}/tmp/patch1.sh

%post -n libdummy_livepatch
/tmp/patch1.sh

%postun

%files -n libdummy_livepatch
%defattr(-,root,root)
/tmp/patch1.so
/tmp/metadata1.ulp
/tmp/patch1.sh
