#!/bin/sh

libtoolize -c
aclocal
automake --add-missing -c --foreign
autoconf
