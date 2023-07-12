# Example: Live Patching a C++ ordinary class
## About
This example illustrates how we can patch static (private), non-inlined functions.
Unfortunatelly, private functions are not publically exposed into the library you want to livepatch. Hence, those functions will not be present in the `.dynsym` table. Furthermore, the program can have multiple different functions with the same signature.

If the target program or library did not have its debug symbols stripped, it is possible to find the private symbols in the `.symtab` section. In this case we can use `readelf` to find the correct address of the function we want to patch. If not, we have to do the same analysis with the original binary `debuginfo`, hopefully distributed by your distribution.

## The example

In this example we have two files: `class.cpp` and `a_livepatch1.cpp`. The first file contains code to calculate the distance to the origin of the 3D point in question. Notice that the method `Norm` calls a private function `norm`, which is not inlined. In the second file there is a livepatch function which will replace `norm` with `norm3_lp`, which will compute the 3-norm instead of the 2-norm.

## Live Patching

This example is crafted so that the function `norm` is not inlined into `Norm`, as can be seen by the `noinline` declaration of it. If you remove this keyword then the function will be inlined and the only way to do the patching would be to livepatch all callers of `norm`. In this case it would be only `Norm`, but in other scenarios there could be thousands of occurences.

### Discovering if function was inlined.

We compile the example with `-fdump-ipa-clones`, which dumps Interprocedural Analysis decisions by GCC -- one being inlining decisions.

For `class.cpp`, a file is generated named `class.cpp.000i.ipa-clones` once you build the example. If you look for references of `norm` in this file you will see:
```
Callgraph clone;_ZL3dotPdS_;1394;class.cpp;8;15;_ZL4normPd;1395;class.cpp;13;24;inlining to
```
which translates that the function `dot` was *inlined into* `norm`. This is not a problem for us. There would only be a problem if `norm` was inlined somewhere, which is not the case.

### Retrieving the offset of target private function

A way to retrieve the target offset function is to use `readelf` to show the offset of each symbol in the target application/library. This piped with `grep` is enough to retrieve the symbol address if the function name is unique. If the function name is not unique then you should check if the function you desire to patch is actually at that address by looking into the assembly dump. If not, then you should proceed to the next occurence until you find it.

To list all offset of symbols matching `norm` in the `test` binary, do:
```
$ readelf -sW | grep 'norm'
```
output:
```
     6: 000000000040122e    41 FUNC    LOCAL  DEFAULT   15 _ZL4normPd
```
This means that the function `_ZL4nromPd` (mangled name for `double norm(double v[3]);`) is available in offset `40122e` hexadecimal. it is also a function (`FUNC`) and it has `LOCAL` visibility.

### Description file with function offsets

The offset of the target function can be specified by appending an extra `:<offset>` to the livepatch symbol replacement specification:
```
_ZL4normPd:_Z8norm3_lpPd:40122e
```
This should be enough so that libpulp patches the correct function at that address.
