#   libpulp - User-space Livepatching Library
#
#   Copyright (C) 2020 SUSE Software Solutions GmbH
#
#   This file is part of libpulp.
#
#   libpulp is free software; you can redistribute it and/or
#   modify it under the terms of the GNU Lesser General Public
#   License as published by the Free Software Foundation; either
#   version 2.1 of the License, or (at your option) any later version.
#
#   libpulp is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#   Lesser General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with libpulp.  If not, see <http://www.gnu.org/licenses/>.

lib_LTLIBRARIES = libpulp.la

libpulp_la_SOURCES = ulp.c ulp_prologue.S ulp_interface.S
libpulp_la_LDFLAGS = -ldl

AM_CFLAGS = -I$(top_srcdir)/include

EXTRA_DIST = trm.S

all-local: trm.o

trm.o: $(srcdir)/trm.S
	$(CPPASCOMPILE) -fPIC -c -o $@ $^

install-exec-local: trm.o
	install -d $(DESTDIR)/$(libdir)
	install -t $(DESTDIR)/$(libdir) $^

uninstall-local:
	rm -f $(DESTDIR)/$(libdir)/trm.o
