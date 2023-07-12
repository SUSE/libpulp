# Example: Live patching template methods
## About

This example illustrates how we can livepatch template methods in C++.

### C++ templates

C++ has the ability to generate code according to given parameters by using
`templates`. This is more powerful than C macros and it is very useful to
generate classes or functions for multiple types or multiple predetermined
bounds.

## The example

In this example we have two files: `class.cpp` and `a_livepatch1.cpp`. The
first file contains a template class `Queue` which generates code for each
type and maximum bound. Here we only use the case where MAX = 32 and types
as `long` and `double`. In the second file we have a livepatch which modifies
the code of `Push` to print a message for each type it runs.

Since the `Queue` is used with two types (`long` and `double`), we have to
generate two functions in the livepatch library. This is shown by the
declarations:
```
/* Output the modified functions for all types generated.  */
template void Queue<QMAX, long>::Push_LP(long x);
template void Queue<QMAX, double>::Push_LP(double x);
```

which will generate two functions `_ZN5QueueILi32ElE7Push_LPEl` and
`_ZN5QueueILi32EdE7Push_LPEd`.

## Live Patching

Unfortunately since C++ `template` functions are generating according to each
one of the template parameters that are given, you must generate one function
for each one parameter that are used in the program. On our example it is easy,
as the project has one file, the template is expanded to only two types, and
functions are not inlined.
