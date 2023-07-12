# Example: Calling private non-inlined non-externalized function available in original binary
## About
This example illustrates how we can use code that is already available in the
original library. For this to work correctly, the function or method should not
have been inlined, so it is callable.

## The example

In this example we have two files: `class.cpp` and `a_livepatch1.cpp`. The
first file contains code to calculate the norm of a 2D point and print its
results. In the second file it contains a livepatch to replace the 2-norm
with a 3-Norm. The print call goes untouched, and since it is not inlined,
the original method can be called without problems.

## Live Patching

This example is crafted so that the method `Print` is not inlined into `Norm`,
as can be seen by the `noinline` declaration of it.

### Reference to non-externalized symbol

Since the symbol is not externalized, we have to get the reference to the
target function manually instead of relying on `ld` to find it to us.

For us to be able to call this method, we must declare a pointer to a method
and call it. This pointer will be filled by libpulp with the address of the
desired method we want to call.

In `a_livepatch.cpp`:
```
extern "C" {
  double (Point::*Print_LP)(double) = nullptr;
}
```

Then on `a_livepatch.dsc`:
```
#_ZN5Point5PrintEd:Print_LP
```

The `#` token will describe that `Print_LP` should be initialized with the
*address* of Point::Print. In case the debug symbols are not available in
the binary, the offset of the symbol can be specified as:
```
#_ZN5Point5PrintEd:Print_LP:4011fe
```
