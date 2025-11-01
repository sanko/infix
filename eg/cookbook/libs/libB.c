/**
 * @file libB.c
 * @brief A dependency library for the library dependency chain example.
 */

// This function is exported from libB and will be called by libA.
int helper_from_lib_b() { return 100; }
