/**
 * @file Ch04_VTableCStyle.c
 * @brief Cookbook Chapter 4: Calling a Function Pointer from a Struct
 *
 * This example demonstrates how to call a function pointer that is a member of
 * a struct. This pattern is common in C for emulating object-oriented v-tables
 * or for creating plugin interfaces.
 *
 * The process is two-step:
 * 1. Read the function pointer from the C struct.
 * 2. Create an `infix` forward trampoline for that specific function pointer's
 *    signature and call it.
 */
#include <infix/infix.h>
#include <stdio.h>
#include <stdlib.h>

// The "object" itself holds the data.
typedef struct {
    int val;
} Adder;

// Forward declare the v-table.
typedef struct AdderVTable_t AdderVTable;

// The "methods" are standalone C functions that take the object as a 'self' pointer.
static int vtable_add(Adder * self, int amount) {
    printf("  -> vtable_add called on Adder at %p with amount %d\n", (void *)self, amount);
    return self->val + amount;
}

static void vtable_destroy(Adder * self) {
    printf("  -> vtable_destroy called on Adder at %p\n", (void *)self);
    free(self);
}

// The v-table struct holds the function pointers.
struct AdderVTable_t {
    int (*add)(Adder * self, int amount);
    void (*destroy)(Adder * self);
};

// A global, constant instance of the v-table.
const AdderVTable VTABLE = {vtable_add, vtable_destroy};

// A "constructor" that allocates an Adder and returns it.
static Adder * create_adder(int base) {
    Adder * a = malloc(sizeof(Adder));
    if (a)
        a->val = base;
    return a;
}

int main() {
    printf("Cookbook Chapter 4: C-Style V-Table Emulation\n");

    // 1. Use the Type Registry to create clean, readable signatures for our types.
    infix_registry_t * reg = infix_registry_create();
    const char * defs =
        // 1. Define the base struct type.
        "@Adder = { val: int };"

        // 2. Create an explicit, named alias for a POINTER to that struct.
        "@AdderPtr = *@Adder;"

        // 3. Now, use the simple pointer alias in the function pointer definitions.
        "@Adder_add_fn = (@AdderPtr, int) -> int;"
        "@Adder_destroy_fn = (@AdderPtr) -> void;"

        // 4. The v-table definition remains the same, using the function pointer aliases.
        "@AdderVTable = { add: @Adder_add_fn, destroy: @Adder_destroy_fn };";
    if (infix_register_types(reg, defs) != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to register types.\n");
        infix_error_details_t err = infix_get_last_error();
        fprintf(stderr, "Infix Error [Code %d, Pos %zu]: %s\n", err.code, err.position, err.message);
        infix_registry_destroy(reg);
        return 1;
    }

    // 2. Create an instance of our C "object".
    Adder * my_adder = create_adder(100);
    const AdderVTable * vtable = &VTABLE;
    printf("C 'object' created at %p with base value 100.\n", (void *)my_adder);

    // 3. Read the function pointer directly from the v-table struct.
    void * add_func_ptr = (void *)vtable->add;

    // 4. Create a trampoline specifically for the `add` function's signature.
    //    The target of this trampoline is the function pointer we just read.
    infix_forward_t * t_add = NULL;
    infix_status status = infix_forward_create(&t_add, "@Adder_add_fn", add_func_ptr, reg);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create trampoline for v-table method.\n");
        free(my_adder);
        infix_registry_destroy(reg);
        return 1;
    }

    // 5. Call the method via the trampoline. The first argument must be the
    //    'self' pointer to the object.
    int amount_to_add = 23;
    int result;
    void * add_args[] = {&my_adder, &amount_to_add};

    printf("Calling the 'add' method via FFI...\n");
    infix_forward_get_code(t_add)(&result, add_args);

    printf("Result from v-table call: %d (Expected: 123)\n", result);

    // 6. Clean up.
    vtable->destroy(my_adder);  // Call destroy directly for simplicity here.
    infix_forward_destroy(t_add);
    infix_registry_destroy(reg);

    return 0;
}
