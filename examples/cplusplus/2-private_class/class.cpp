#include <iostream>
#include <unistd.h>
#include <math.h>

typedef double vec3_t[3];
#define noinline __attribute__((noinline))

static double dot(vec3_t u, vec3_t v)
{
  return u[0]*v[0] + u[1]*v[1] + u[2]*v[2];
}

// Will be livepatched.
static noinline double norm(vec3_t v)
{
  return sqrt(dot(v, v));
}

class Point
{
  protected:
  double x, y;

  public:
  Point(double x, double y);

  double Get_X(void) const;
  double Get_Y(void) const;
};

class Point3D : public Point
{
  protected:
  double z;

  public:
  Point3D(double x, double y, double z);
  double Norm(void);

  double Get_Z(void) const;

};

double Point::Get_X(void) const
{
  return x;
}

double Point::Get_Y(void) const
{
  return y;
}

Point::Point(double x, double y)
{
  this->x = x;
  this->y = y;
}

Point3D::Point3D(double x, double y, double z) : Point(x, y)
{
  this->z = z;
}

double Point3D::Get_Z(void) const
{
  return z;
}

double Point3D::Norm(void)
{
  vec3_t v = {x, y, z};
  return norm(v);
}

extern "C" double some_function(vec3_t v)
{
  return norm(v) * norm(v);
}

int main(void)
{
  Point3D p(3, 4, 5);
  while (1) {
    std::cout << p.Norm() << '\n';
    sleep(1);
  }

  return 0;
}
