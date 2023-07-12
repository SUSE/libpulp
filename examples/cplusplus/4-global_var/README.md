# Example: Calling private non-inlined non-externalized function available in original binary
## About

This example illustrates how we can access global variables -- private or
public -- as it may be necessary to create a livepatch. One case where such cases
may happen is to access global locks, as shown in this example.

In `test.cpp`, there is an accumulator that is protected by a mutex lock. A
livepatch that touches this critical section will have to lock it before doing
any modifications to the `sum` variable.

## The example

In this example we have two files: `test.cpp` and `a_livepatch1.cpp`. The
first file contains code to accumulate into a variable using multiple
threads. The second file contains a patch that set that variable to 0.

## Live Patching

In order to create this livepatch, we have to setup references to the global
variables that needs to be modified. On `a_livepatch.cpp`:
```
volatile long *sum_ptr = NULL;
pthread_mutex_t *sum_lock_ptr = NULL;
```
Then on .dsc:
```
#sum:sum_ptr
#sum_lock:sum_lock_ptr
```

with this, the pointers `sum_ptr` and `sum_lock_ptr` will be initialized with
the address of `sum` and `sum_lock`.
