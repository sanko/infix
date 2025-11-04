/**
 * @file Ch02_AdvancedRegistry.c
 * @brief Cookbook Chapter 2: Advanced Named Types (Recursive & Forward-Declared)
 *
 * This example demonstrates the full power of the `infix` Type Registry to model
 * complex, real-world C data structures. It shows how to define:
 * 1. A recursive type (a linked list `@Node`).
 * 2. Mutually-recursive types (`@Employee` and `@Manager`) using forward declarations.
 */
#include <infix/infix.h>
#include <stdio.h>

// C equivalent of the mutually-recursive types we will define:
typedef struct Employee Employee;
typedef struct Manager {
    const char * name;
    Employee * reports[10];  // A manager has direct reports
} Manager;

struct Employee {
    const char * name;
    Manager * manager;  // An employee has a manager
};

// A simple C function to demonstrate usage with these types.
static const char * get_manager_name(Employee * e) { return e->manager ? e->manager->name : "None"; }

int main() {
    printf("--- Cookbook Chapter 2: Advanced Named Types ---\n");

    infix_registry_t * registry = infix_registry_create();
    if (!registry) {
        fprintf(stderr, "Failed to create registry.\n");
        return 1;
    }

    // 1. Define the types in a string. Note the forward declarations (`@Name;`)
    //    which are necessary because Manager refers to Employee, and vice-versa.
    //    The parser handles out-of-order and recursive definitions automatically.
    const char * definitions =
        "@Employee; @Manager;"  // Forward declarations
        "@Manager = { name:*char, reports:[10:*@Employee] };"
        "@Employee = { name:*char, manager:*@Manager };";
    if (infix_register_types(registry, definitions) != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to register types.\n");
        infix_registry_destroy(registry);
        return 1;
    }
    printf("Successfully registered mutually-recursive types.\n");

    // 2. Create a trampoline using the named types.
    infix_forward_t * trampoline = NULL;
    infix_status status =
        infix_forward_create(&trampoline, "(*@Employee) -> *char", (void *)get_manager_name, registry);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create trampoline.\n");
        infix_registry_destroy(registry);
        return 1;
    }
    infix_cif_func cif = infix_forward_get_code(trampoline);

    // 3. Set up the C data structures and call the function.
    Manager boss = {"Sanko", {NULL}};
    Employee worker = {"Robinson", &boss};
    Employee * p_worker = &worker;
    const char * manager_name = NULL;
    void * args[] = {&p_worker};

    cif(&manager_name, args);

    printf("Calling get_manager_name() via FFI...\n");
    printf("The manager of %s is %s. (Expected: Sanko)\n", worker.name, manager_name);

    // 4. Clean up.
    infix_forward_destroy(trampoline);
    infix_registry_destroy(registry);

    return 0;
}
