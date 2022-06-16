This folder contains valid inputs for ulp tools, with PWD in test dir.
Those files are used by AFL, a fuzzer which mutates the arguments input
to the `ulp` program.

Every parameter should be separated with NUL character in order to AFL
correctly detects as being different arguments for argv.
