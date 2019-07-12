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

Name:           libdummy_livepatch_2
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
%define patchdir /var/ulp/%{name}-%{version}

# tricky part: we need to build using libdummy 0.1 binaries, but before
# installing, we need to make sure that these binaries are up to date
BuildRequires:	dummyapp = 0.1
BuildRequires:	libpulp
Requires:	libpulp
Requires:	lua53

%description
This package provides a livepatch for libdummy.

%prep
%setup -q -n libdummy_livepatch_2-%{version}

%build
./build-livepatch.sh

%install
mkdir -p %{buildroot}%{patchdir}
mv ./build/patch2.so %{buildroot}%{patchdir}/patch2.so
mv ./build/metadata2.ulp %{buildroot}%{patchdir}/metadata2.ulp
mv ./build/reverse2.ulp %{buildroot}%{patchdir}/reverse2.ulp

%post -n libdummy_livepatch_2
lua %{_bindir}/ulp_dispatcher patch %{patchdir}/metadata2.ulp

%preun
lua %{_bindir}/ulp_dispatcher patch %{patchdir}/reverse2.ulp

%files -n libdummy_livepatch_2
%defattr(-,root,root)
%{patchdir}/patch2.so
%{patchdir}/metadata2.ulp
%{patchdir}/reverse2.ulp
