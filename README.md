# Libpulp

[![status](https://github.com/inconstante/cicdtest/actions/workflows/test-suite.yml/badge.svg)](https://github.com/inconstante/cicdtest/actions/workflows/test-suite.yml)

# Table of contents

1. [Introduction](#introduction)
    1. [Getting started](#getting-started)
    1. [License](#license)
    1. [Known issues](#known-issues)
1. [Contributing](#contributing)
    1. [Coding style](#coding-style)
    1. [Project structure](#project-structure)
1. [Consistency](#consistency)
1. [The patching process](#the-patching-process)
1. [Description file syntax](#description-file-syntax)

# Introduction

Libpulp is a framework that enables userspace live patching. It is composed of a
library per se and a collection of tools used in the preparation of
live-patchable libraries and in the application of live patches to running
processes. In order to be live-patchable, a library must be compiled with
patchable function entries<sup>1</sup>, then post-processed with the _post_
tool, but no changes to the library source-code are needed. Apart from that,
processes must preload <sup>2</sup> _libpulp.so_ in order to be live-patchable.

<sup>1</sup> _GCC provides the -fpatchable-function-entry option, which adds nop
instructions to the prologue of functions. These nops are used by Libpulp to
divert the execution flow when live patches are applied._

<sup>2</sup> _Live-patchable libraries do not explicitly require libpulp to be
loaded at process initialization, instead, system administrators must start
processes with LD_PRELOAD=libpulp.so, when they want to be able to live patch
them._

## Getting started

Building and running the test suite is probably the fastest way to get started
with Libpulp. The build system is based on GNU autotools, so, from a fresh
checkout of the repository, the typical build commands are enough:

```
./bootstrap
./configure
make
make check
```

The test suite, apart from avoiding unintentional regressions during
development, provides several examples on how to use Libpulp. The oldest of the
test cases, _numserv.py_, is also one of the easiest to understand: it starts
the _numserv_ application, which loads two live-patchable libraries, then
interacts with it, applying live patches and checking the results. It is a good
place to get started. Likewise, the _parameters.py_ test case is also simple and
a good starting point.

## License

Libpulp is free software; you can redistribute it and/or modify it under the
terms of the GNU Lesser General Public License as published by the Free Software
Foundation; either version 2.1 of the License, or (at your option) any later
version.

## Known issues

### Requirement on automake 1.16

Even though the build system makes heavy use of automake, a few rules in the
Makefiles have been manually written. Such rules do not play well with versions
of automake older than 1.16. When older versions are used, the following build
problem might happen:

```
Making all in tests
make[1]: Entering directory '/home/gabriel/libpulp/tests'
Makefile:1174: ../lib/.deps/trm.Plo: No such file or directory
make[1]: *** No rule to make target '../lib/.deps/trm.Plo'.  Stop.
make[1]: Leaving directory '/home/gabriel/libpulp/tests'
make: *** [Makefile:421: all-recursive] Error 1
```

To work around this problem, disable dependency tracking during configuration:

```
./configure --disable-dependency-tracking
```

# Contributing

Contributions are welcome! You are welcome to open bug reports at the git
hosting platform, submit patches through merge requests, or email any of them to
our mailing list (https://lists.opensuse.org/ulp-devel).

## Coding Style

The easiest way to adhere to the coding style is to use the following command,
which will read the contents of the .clang-format file and apply the rules
described in it to _filename_. However, notice that using this only makes sense
with .c and .h files.

```
clang-format -style=file _filename_
```

The style is the same that is used in the GNU project, except that:

  1. Eight spaces DO NOT become a TAB character; TABs are avoided;
  2. Opening curly braces in control statements (if, while, switch, etc) remain
     on the same line; only curly braces on the first column, such as for
     function and struct definitions, need a newline;
  3. Opening parentheses are only preceded by a space in controls statements
     (if, while, switch, etc); not in function or macro calls;
  4. Cases in switch statements add one indentation level;
  5. Backslashes at the end of lines need not be aligned;
  6. Breaking lines either before or after operators are allowed.

## Project structure

The directory hierarchy is divided into the following major components:

#### lib

This directory mostly contains the files that make-up _libpulp.so_, the library
that programs must preload to become live-patchable processes. This library is
built from just a few files: _ulp.c_, which contains the bulk of the live
patching routines; _ulp_prologue.S_, which contains a routine that live patched
functions call to save and restore registers; and _ulp_interface.S_, which
contains the entry-point functions that the _Trigger_ and _Check_ tools use to
apply and check live patches.

Also in this directory, _trm.S_ produces the object that libraries need to
link against in order to become live-patchable. It contains the library entrance
tracking routine (see [Consistency](#consistency)), as well as routines to
retrieve the value of thread-local counters.

#### tools

The following tools comprise the tool set of Libpulp:

 * _Post_: This tool is used to modify the library entry points to the special
   instrumentation used by Libpulp to track consistency. It modifies the values
   of the targets in the dynamic symbol table to, instead of pointing to the
   regular function, point to the trampoline of each function; as well as it
   writes the trampolines themselves.

 * _Packer_: This tool creates the live patch metadata out of a description file
   and from the targeted library. The description file syntax is described in
   its own [section](#description-file-syntax).

 * _Trigger_: This tool is used to introspect into the to-be-patched process and
   trigger the live patching process.

 * _Check_: This tool introspects into a target process and verifies if a given
   patch was applied.

 * _Dump_: This tool parses and dumps the contents of a live patch metadata file.

 * _Ulp_: This tool searches the system for live-patchable processes and report
   their state.

 * _Dispatcher_: This tool retrieves the to-be-patched library from the live
   patch metadata file and verifies all the running process which have the
   target library loaded. If the argument "patch" is supplied, it invokes the
   trigger tool for every process in the list. If the argument "check" is
   supplied, it only verifies if the given process was previously patched.

#### tests

This directory contains everything related to the test suite, which can be
execute with 'make check'. Python files are scripts that start the to-be-patched
processes (preloading _libpulp.so_), apply live patches, and poke them to verify
that their outputs changed accordingly. Files with the _\_livepatch_ suffix are
built into the live patches per se. Everything else is test libraries and
applications.

# Consistency

To ensure correct program semantics, it is important to keep atomicity during
the execution of live patchable functions. This means that, for each thread in
the affected process, all the functions which are part of a live patch set are
migrated to their newer versions simultaneously.

To achieve this, all replacement functions loaded by a live patch become
associated with a single and unique number, so that they are all perceived as
belonging to the same universe (snapshot) of the program. Apart from that, each
thread in the process has a thread-local counter, which is compared against
those unique numbers to select between original and replacement functions.

Whenever a thread is within a library, its thread-local counter does not change,
so it uses functions from the same universe. Then, when the thread crosses the
application-library boundary, the thread-local counter gets update and new
library calls use new functions all at once, even if there are intra-library
calls (notice that intra-library calls do not update the thread-local counter).

# The patching process

A live patch is built on top of existing libraries. The Libpulp framework
provides the tools to create the patches. Once the patch is created, it is
applied through a ptrace-based tool, that will: attach to the target process;
check if it is compliant with live patching; verify that the target library
is properly loaded into its address space; through control-flow redirection, use
routines from Libpulp to make the process load the new version of the functions
to its address space; then, through adding detours to the old function
prologues, ensure that only the new version of the functions are invoked.

The detours are not patched directly on top of previously existing instructions.
Instead, the function must be emitted by gcc with an area of padding nops which
is then overwritten. This is important to enable per-thread migration of
universes -- by having a thread-local variable which flags if a given thread
was already migrated into a new universe or not, it is possible to decide,
upon function invocation, if the newer or older version of the function must
be reached by the control-flow. In this scenario, in the moment of the patch
application, a thread which has functions from the target library in an active
state won't be migrated, and the older version will continue to be reached.
Through using the instrumentation in the function entry points, this thread
can later migrate itself safely (given that an entering library is always
consistent).

# Description file syntax

The live patching metadata is built from a description file which should be
written with the following syntax:

```
1: <absolute path of .so with patching functions>
2: @<absolute path of the targeted library>
3: <old_fname_1>:<new_fname_1>
4: <old_fname_2>:<new_fname_2>
...
```

Line 1 brings the absolute path of a .so file that contains all the functions
which will be used to replace functions in the running process. Line 2 brings
the absolute path for the library that will be patched and must be preceded by
an '@'. The following lines bring pairs of replaced and replacing functions.
