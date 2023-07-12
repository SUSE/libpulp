#include <iostream>
#include <unistd.h>
#include <math.h>

#define noinline __attribute__((noinline))

class Point
{
  private:
  void noinline Print(double n);

  protected:
  double x, y;

  public:
  Point(double x, double y);
  double Norm(void);
};

Point::Point(double x, double y)
{
  this->x = x;
  this->y = y;
}

// Will be livepatched;
double Point::Norm(void)
{
  double n = sqrt(x*x + y*y);
  Print(n);
  return n;
}

void noinline Point::Print(double n)
{
  std::cout << "Point: " << x << ' ' << y << ' ' << "Have norm2 = " << n <<'\n';
}

int main(void)
{
  Point p(3, 4);
  while (1) {
    p.Norm();
    sleep(1);
  }

  return 0;
}
