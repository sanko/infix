/**
 * @file Ch06_Rec02_GlobalVariables.c
 * @brief Cookbook Chapter 6, Recipe 2: Reading and Writing Global Variables
 *
 * This example demonstrates how to use `infix_read_global` and `infix_write_global`
 * to interact with global variables exported from a shared library. The `infix`
 * signature language is used to describe the type of the variable, ensuring that
 * the correct number of bytes are read or written, which prevents memory corruption.
 */
#include <infix/infix.h>
#include <stdio.h>
#include <string.h>

// A C struct that matches the layout of the one in the shared library.
typedef struct {
    const char * name;
    int version;
} Config;

// The name of the shared library to load.
#if defined(_WIN32)
const char * LIB_NAME = "globals.dll";
#else
const char * LIB_NAME = "./libglobals.so";
#endif

int main() {
    printf("--- Cookbook Chapter 6, Recipe 2: Reading and Writing Global Variables ---\n");

    infix_library_t * lib = infix_library_open(LIB_NAME);
    if (!lib) {
        fprintf(stderr, "Failed to open library '%s'.\n", LIB_NAME);
        return 1;
    }

    // Example 1: Simple Integer Variable
    printf("\n-- Interacting with 'global_counter' (int) --\n");
    int counter_val = 0;

    // 1. Read the initial value of the integer global.
    infix_read_global(lib, "global_counter", "int", &counter_val, NULL);
    printf("Initial value of global_counter: %d (Expected: 42)\n", counter_val);

    // 2. Write a new value to the global variable.
    int new_val = 100;
    printf("Writing new value (100) to global_counter...\n");
    infix_write_global(lib, "global_counter", "int", &new_val, NULL);

    // 3. Read the value again to confirm the change.
    counter_val = 0;  // Reset local variable to be sure.
    infix_read_global(lib, "global_counter", "int", &counter_val, NULL);
    printf("New value of global_counter: %d (Expected: 100)\n", counter_val);

    // Example 2: Aggregate (Struct) Variable
    printf("\n-- Interacting with 'g_config' (struct) --\n");
    infix_registry_t * reg = infix_registry_create();
    infix_register_types(reg, "@Config = {*char, int};");

    Config local_config;
    memset(&local_config, 0, sizeof(Config));

    // 1. Read the global struct into our local variable.
    infix_read_global(lib, "g_config", "@Config", &local_config, reg);
    printf("Initial config: name='%s', version=%d (Expected: 'default', 1)\n", local_config.name, local_config.version);

    // 2. Modify and write the struct back to the library.
    Config new_config = {"updated", 2};
    printf("Writing new config ('updated', 2) to g_config...\n");
    infix_write_global(lib, "g_config", "@Config", &new_config, reg);

    // 3. Read it back to verify.
    memset(&local_config, 0, sizeof(Config));
    infix_read_global(lib, "g_config", "@Config", &local_config, reg);
    printf("Updated config: name='%s', version=%d (Expected: 'updated', 2)\n", local_config.name, local_config.version);

    // Clean up
    infix_registry_destroy(reg);
    infix_library_close(lib);

    return 0;
}
