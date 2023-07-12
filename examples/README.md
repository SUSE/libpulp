# Userspace Livepatch Examples.

This folder contain livepatching examples. Once you compile the example hitting
`make`, it will generate two files:

1. `test`
2. `a_livepatch1.so`

The first file is a binary and should be run with `libpulp.so` loaded. Assuming
libpulp is installed in `/usr/local/lib64/libpulp.so.0`, that is:
```
$ LD_PRELOAD=/usr/local/lib64/libpulp.so.0 ./test
```

The second file is the livepatch and should be applied with the `ulp` tool by
running:
```
$ ulp trigger a_livepatch.so
```

Have fun and happy livepatching!
