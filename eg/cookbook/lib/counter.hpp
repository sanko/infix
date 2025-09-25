#pragma once

#ifdef __cplusplus
// This entire class definition is now only visible to C++ compilers.
class Counter {
public:
    Counter();
    void add(int value);
    int get() const;

private:
    int count;
};
#endif

// The C-style wrapper API, visible to both C and C++.
#ifdef __cplusplus
extern "C" {
#endif

// The C compiler sees this as an opaque struct forward declaration.
// The C++ compiler understands it's referring to the class above.
typedef struct Counter Counter;

// These are the pure C function prototypes that both compilers will see.
Counter * Counter_create();
void Counter_destroy(Counter * c);
void Counter_add(Counter * c, int value);
int Counter_get(Counter * c);

#ifdef __cplusplus
}
#endif
