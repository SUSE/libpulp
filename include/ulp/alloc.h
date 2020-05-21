#ifndef _ULP_ALLOC_H
#define _ULP_ALLOC_H

void *
ulp_scratch_alloc (int size);

void *
ulp_default_alloc (int size);

int
ulp_scratch_clear (void);

#endif
