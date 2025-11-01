/**
 * @file libA.c
 * @brief A shared library that depends on another shared library (libB).
 */

// Declare the function imported from libB.
// The linker will resolve this at load time.
int helper_from_lib_b();

// The main entry point for this library that we will call from our example.
int entry_point_a() {
    // This function calls a function from its dependency.
    return 200 + helper_from_lib_b();
}
