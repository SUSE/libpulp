#include <iostream>
#include <unistd.h>

class Point
{
  protected:
  int x, y;

  public:
  Point(int x, int y);

  int Get_X(void) const;
  int Get_Y(void) const;

  void Print(void);
};

class Point3D : public Point
{
  protected:
  int z;

  public:
  Point3D(int x, int y, int z);

  int Get_Z(void) const;

  void Print(void);
};

int Point::Get_X(void) const
{
  return x;
}

int Point::Get_Y(void) const
{
  return y;
}

// Will be livepatched
void Point::Print(void)
{
  std::cout << Get_X() << ' ' << Get_Y() << '\n';
}

Point::Point(int x, int y)
{
  this->x = x;
  this->y = y;
}

Point3D::Point3D(int x, int y, int z) : Point(x, y)
{
  this->z = z;
}

int Point3D::Get_Z(void) const
{
  return z;
}

// Will be livepatched
void Point3D::Print(void)
{
  std::cout << Get_X() << ' ' << Get_Y() << ' ' << Get_Z() << '\n';
}

int main(void)
{
  Point3D p(3, 4, 5);
  while (1) {
    p.Print();
    sleep(1);
  }

  return 0;
}
