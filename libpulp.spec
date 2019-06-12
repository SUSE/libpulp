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

Name:           libpulp
Version:	0.1
Release:	0
License:	SUSE-GPL-2.0
Summary:	User-space Livepatching Library
Source0:	%{name}-%{version}.tar.bz2

%define topdir %(echo $PWD)/rpmbuild
%define _builddir %{topdir}/build
%define _rpmdir %{topdir}/rpms
%define _sourcedir %(echo $PWD)
%define _specdir %(echo $PWD)
%define _srcrpmdir %{topdir}/rpms

BuildRequires: gcc
BuildRequires: binutils_ulp
BuildRequires: libelf-devel
BuildRequires: binutils-devel

%description
This package provides libpulp. Also, example applications.

%prep
%setup -q -n libpulp-%{version}

%build
cd rpm
./build-lib.sh

%install
mkdir -p %{buildroot}%_bindir
mkdir -p %{buildroot}/usr/ulp/libpulp
mkdir -p %{buildroot}/var/ulp/
mv rpm/build/libpulp.so %{buildroot}/usr/ulp/libpulp/libpulp.so
mv rpm/build/trigger %{buildroot}%_bindir/ulp_trigger
mv rpm/build/packer %{buildroot}%_bindir/ulp_packer
mv rpm/build/dynsym_gate %{buildroot}%_bindir/ulp_dynsym_gate
mv rpm/build/checker %{buildroot}%_bindir/ulp_check
mv tools/dispatcher/dispatcher.lua %{buildroot}%_bindir/ulp_dispatcher

%files -n libpulp
%defattr(-,root,root)
/usr/ulp/libpulp/libpulp.so
%{_bindir}/ulp_trigger
%{_bindir}/ulp_packer
%{_bindir}/ulp_dynsym_gate
%{_bindir}/ulp_check
%{_bindir}/ulp_dispatcher
