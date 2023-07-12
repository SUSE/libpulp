#include <math.h>

typedef double vec3_t[3];

double norm3_lp(vec3_t v)
{
  return cbrt(v[0]*v[0]*v[0] + v[1]*v[1]*v[1] + v[2]*v[2]*v[2]);
}
