#include <iostream>

class Point
{
  protected:
  int x, y;

  public:
  Point(int x, int y);

  int Get_X(void) const;
  int Get_Y(void) const;

  void Print_LP(void);
};

class Point3D : public Point
{
  protected:
  int z;

  public:
  Point3D(int x, int y, int z);

  int Get_Z(void) const;

  void Print_LP(void);
};

void Point::Print_LP(void)
{
  std::cout << x + 1 << ' ' << y + 1 << '\n';
}

void Point3D::Print_LP(void)
{
  std::cout << x + 1 << ' ' << y + 1 << ' ' << z << '\n';
}
