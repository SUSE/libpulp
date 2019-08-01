#include <stdio.h>

extern int fibo(int n);

int new_fibo(int n)
{
    if (n < 2) return n;
    else return fibo(n - 1) + fibo(n - 2);
}
