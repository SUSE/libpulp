#include <math.h>

class Point
{
  private:
  void Print(double n);

  protected:
  double x, y;

  public:
  Point(double x, double y);
  double Norm_LP(void);
};

/** This global variable will contain the address of Point::Print once the
    livepatch is installed.  */
extern "C" {
  double (Point::*Print_LP)(double) = nullptr;
}


double Point::Norm_LP(void)
{
  double n = cbrt(x*x*x + y*y*y);

  /** Since we declare it as a function, we must explicitely pass the 'this'
      pointer.  */
  (this->*Print_LP)(n);
  return n;
}
