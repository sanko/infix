/**
 * @file shapes.cpp
 * @brief A simple polymorphic C++ class hierarchy for the virtual function FFI example.
 */
#include <cmath>

// On Windows, M_PI is not always defined in <cmath>
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

class Shape {
public:
    virtual double area() const = 0;        // 1st virtual function (index 0)
    virtual const char * name() const = 0;  // 2nd virtual function (index 1)
    virtual ~Shape() = default;
};

class Rectangle : public Shape { public:
    double w, h;

public:
    Rectangle(double width, double height) : w(width), h(height) {}
    double area() const override { return w * h; }
    const char * name() const override { return "Rectangle"; }
};

class Circle : public Shape {
    double r;

public:
    Circle(double radius) : r(radius) {}
    double area() const override { return M_PI * r * r; }
    const char * name() const override { return "Circle"; }
};

// extern "C" factory functions to create C++ objects from C.
extern "C" {
Shape * create_rectangle(double w, double h) { return new Rectangle(w, h); }
double fdfdsafdsa(Rectangle * shape){ return shape->w;}
Shape * create_circle(double r) { return new Circle(r); }
void destroy_shape(Shape * s) { delete s; }
}
