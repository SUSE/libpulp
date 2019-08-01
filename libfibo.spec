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

Name:           libfibo
Version:	0.1
Release:	0
License:	SUSE-GPL-2.0
Summary:	Dummy library example for user space live patching
Group:		System/Libraries
Provides:	libfibo = %{version}
Source0:	%{name}-%{version}.tar.bz2

%define topdir %(echo $PWD)/rpmbuild
%define _builddir %{topdir}/build
%define _rpmdir %{topdir}/rpms
%define _sourcedir %(echo $PWD)
%define _specdir %(echo $PWD)
%define _srcrpmdir %{topdir}/rpms

BuildRequires:	gcc_ulp
BuildRequires:	binutils_ulp
BuildRequires:	libpulp

%description
This package brings the libpulp fibonacci example

%package -n fiboapp
Summary:	Application that uses libfibo and will be patched
Group:		Development/Tools/Other
Provides:	fiboapp

%description -n fiboapp
Application to be patched in libpulp examples.

%prep
%setup -q -n libfibo-%{version}

%build
./build-libfibo.sh

%install
mkdir -p %{buildroot}%_bindir/
mkdir -p %{buildroot}/usr/ulp/libfibo/
mv build/ex1 %{buildroot}%_bindir/fiboapp
mv build/libfibo.so %{buildroot}/usr/ulp/libfibo/libfibo.so

%files -n fiboapp
%defattr(-,root,root)
%{_bindir}/fiboapp

%files -n libfibo
/usr/ulp/libfibo/*
