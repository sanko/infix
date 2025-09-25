#include "counter.hpp"
#include <iostream>

// --- C++ Class Implementation ---
Counter::Counter() : count(0) {
    std::cout << "[C++] Counter object created." << std::endl;
}

void Counter::add(int value) {
    this->count += value;
}

int Counter::get() const {
    return this->count;
}

// --- C Wrapper Implementation ---
// This is the bridge between the C++ object-oriented world and the C procedural world.
extern "C" {
Counter * Counter_create() {
    return new Counter();
}

void Counter_destroy(Counter * c) {
    std::cout << "[C++] Counter object destroyed." << std::endl;
    delete c;
}

void Counter_add(Counter * c, int value) {
    c->add(value);
}

int Counter_get(Counter * c) {
    return c->get();
}
}
