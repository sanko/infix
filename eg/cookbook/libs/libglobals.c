/**
 * @file libglobals.c
 * @brief A simple shared library that exports global variables for FFI testing.
 */

#if defined(_WIN32)
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

// A simple exported integer variable.
EXPORT int global_counter = 42;

// An exported struct variable.
typedef struct {
    const char * name;
    int version;
} Config;

EXPORT Config g_config = {"default", 1};
