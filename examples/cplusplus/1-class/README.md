# Example: Live Patching a C++ ordinary class
## About
In this test we have two files: `class.cpp` and `a_livepatch1.cpp`. The first
one contain code in C++ for a test program which print the contents of a
`point` class, where the second one contains a livepatch that modifies the
`Print` method so it prints content differently.

## Live Patching C++ methods
C++ methods can be live patched the same way as C functions. However, for
libpulp to find the symbols in the original target binary, you should write
the mangled name instead of the C++ original name of the method.

So instead of writing `Point3D::Print`, one should write `_ZN7Point3D5PrintEv`.
The original declaration of the class should be copied as well (see
`a_livepatch1.cpp` and `a_livepatch1.dsc`).
