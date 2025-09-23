

# The `infix` FFI Cookbook

This guide provides practical, real-world examples to help you solve common FFI problems and leverage the full power of the `infix` library. Where the `README.md` covers concepts, this cookbook provides the code.

## Table of Contents

*   **Chapter 1: The Basics (Forward Calls)**
    *   [Recipe: Calling a Simple C Function](#recipe-calling-a-simple-c-function)
    *   [Recipe: Passing and Receiving Pointers](#recipe-passing-and-receiving-pointers)
    *   [Recipe: Working with Opaque Pointers (Incomplete Types)](#recipe-working-with-opaque-pointers-incomplete-types)
    *   [Recipe: Working with Fixed-Size Arrays](#recipe-working-with-fixed-size-arrays)
*   **Chapter 2: Handling Complex Data Structures**
    *   [Recipe: Dynamic Struct Marshalling with the Signature Parser](#recipe-dynamic-struct-marshalling-with-the-signature-parser)
    *   [Recipe: Small Structs Passed by Value](#recipe-small-structs-passed-by-value)
    *   [Recipe: Large Structs Passed by Reference](#recipe-large-structs-passed-by-reference)
    *   [Recipe: Receiving a Struct from a Function](#recipe-receiving-a-struct-from-a-function)
    *   [Recipe: Working with Packed Structs via the Signature API](#recipe-working-with-packed-structs-via-the-signature-api)
    *   [Recipe: Working with Unions](#recipe-working-with-unions)
    *   [Recipe: Working with Pointers to Arrays](#recipe-working-with-pointers-to-arrays)
*   **Chapter 3: The Power of Callbacks (Reverse Calls)**
    *   [Recipe: Creating a Stateless Callback for `qsort`](#recipe-creating-a-stateless-callback-for-qsort)
    *   [Recipe: Callbacks with State (Adapting to a Stateless C API)](#recipe-callbacks-with-state-adapting-to-a-stateless-c-api)
*   **Chapter 4: Advanced Techniques**
    *   [Recipe: Calling Variadic Functions like `printf`](#recipe-calling-variadic-functions-like-printf)
    *   [Recipe: Creating a Variadic Callback](#recipe-creating-a-variadic-callback)
    *   [Recipe: Proving Reentrancy with Nested FFI Calls](#recipe-proving-reentrancy-with-nested-ffi-calls)
    *   [Recipe: Receiving and Calling a Function Pointer](#recipe-receiving-and-calling-a-function-pointer)
*   **Chapter 5: Interoperability with Other Languages**
    *   [The Universal Principle: The C ABI](#the-universal-principle-the-c-abi)
    *   [Part 1: The C++ Master Example](#part-1-the-c-master-example)
    *   [Part 2: The Pattern for Other Compiled Languages](#part-2-the-pattern-for-other-compiled-languages)
        *   [Rust](#rust)
        *   [Fortran](#fortran)
        *   [Zig](#zig)
        *   [Go](#go)
        *   [Swift](#swift)
        *   [D (dlang)](#d-dlang)
        *   [Assembly (NASM)](#assembly-nasm)
*   **Chapter 6: Calling System Libraries**
    *   [Recipe (Windows): Displaying a `MessageBox`](#recipe-windows-displaying-a-messagebox)
    *   [Recipe (macOS): Interacting with CoreFoundation Objects](#recipe-macos-interacting-with-corefoundation-objects)
    *   [Recipe (Linux/POSIX): Getting System Information](#recipe-linuxposix-getting-system-information)
*   **Chapter 7: Memory Management & Performance**
    *   [Understanding Generation vs. Call-Time Overhead](#understanding-generation-vs-call-time-overhead)
    *   [Best Practice: Caching Trampolines](#best-practice-caching-trampolines)
*   **Chapter 8: Common Pitfalls & Troubleshooting**
    *   [Mistake: Passing a Value Instead of a Pointer in `args[]`](#mistake-passing-a-value-instead-of-a-pointer-in-args)
    *   [Mistake: `ffi_type` Mismatch](#mistake-ffi_type-mismatch)
    *   [Mistake: Forgetting to Free Dynamic `ffi_type` Objects](#mistake-forgetting-to-free-dynamic-ffi_type-objects)
*   **Chapter 9: Building Language Bindings**
    *   [The Four Pillars of a Language Binding](#the-four-pillars-of-a-language-binding)

---

## Chapter 1: The Basics (Forward Calls)

### Recipe: Calling a Simple C Function

**Problem**: You want to call a standard C function, like `int add(int, int);`.

**Solution**: Describe the function's signature using the Signature API, prepare the arguments, and make the call.

```c
#include <infix.h>
#include <stdio.h>

int add_ints(int a, int b) { return a + b; }

int main() {
    // 1. Describe the signature: int(int, int)
    const char* signature = "i,i=>i";

    // 2. Generate the trampoline.
    ffi_trampoline_t* trampoline = NULL;
    ffi_create_forward_trampoline_from_signature(&trampoline, signature);

    // 3. Prepare arguments. The args array holds *pointers* to the values.
    int a = 40, b = 2;
    void* args[] = { &a, &b };
    int result = 0;

    // 4. Get the callable function and invoke it.
    ffi_cif_func cif_func = (ffi_cif_func)ffi_trampoline_get_code(trampoline);
    cif_func((void*)add_ints, &result, args);

    printf("Result of add_ints(40, 2) is: %d\n", result); // Expected: 42

    // 5. Clean up.
    ffi_trampoline_free(trampoline);
    return 0;
}
```

### Recipe: Passing and Receiving Pointers

**Problem**: You need to call a C function that takes pointers as arguments, like `void swap(int* a, int* b);`.

**Solution**: Use the `*` modifier in the signature string. The values you pass in the `args` array are the addresses of your pointer variables.

```c
#include <infix.h>
#include <stdio.h>

void swap_ints(int* a, int* b) {
    int temp = *a;
    *a = *b;
    *b = temp;
}

int main() {
    // 1. Signature: void(int*, int*)
    const char* signature = "i*,i*=>v";
    ffi_trampoline_t* trampoline = NULL;
    ffi_create_forward_trampoline_from_signature(&trampoline, signature);

    // 2. Prepare arguments.
    int x = 10, y = 20;
    int* ptr_x = &x; // These are the actual arguments.
    int* ptr_y = &y;

    // The args array holds pointers *to our pointers*.
    void* args[] = { &ptr_x, &ptr_y };

    printf("Before swap: x = %d, y = %d\n", x, y);

    // 3. Call the function.
    ffi_cif_func cif_func = (ffi_cif_func)ffi_trampoline_get_code(trampoline);
    cif_func((void*)swap_ints, NULL, args);

    printf("After swap: x = %d, y = %d\n", x, y); // Expected: x = 20, y = 10

    ffi_trampoline_free(trampoline);
    return 0;
}
```

### Recipe: Working with Opaque Pointers (Incomplete Types)

**Problem**: You need to interact with a C library that uses opaque pointers (or "handles") where the internal structure is hidden.

**Solution**: Use the `v*` signature for `void*` or any other opaque pointer type. This is the canonical representation for a generic handle.

#### The C "Library" (`handle_lib.h`/`.c`)
```c
// handle_lib.h
struct my_handle; // Opaque struct declaration
typedef struct my_handle my_handle_t;

my_handle_t* create_handle(int initial_value);
void destroy_handle(my_handle_t* handle);
int get_handle_value(my_handle_t* handle);
```

#### The `infix` C Code
```c
#include <infix.h>
#include "handle_lib.h"

int main() {
    // 1. Create trampolines for the C API using signatures.
    ffi_trampoline_t *t_create, *t_destroy, *t_get;
    ffi_create_forward_trampoline_from_signature(&t_create, "i=>v*");
    ffi_create_forward_trampoline_from_signature(&t_destroy, "v*=>v");
    ffi_create_forward_trampoline_from_signature(&t_get, "v*=>i");

    // 2. Use the API through the trampolines.
    my_handle_t* handle = NULL;
    int initial_val = 123;
    void* create_args[] = { &initial_val };
    ((ffi_cif_func)ffi_trampoline_get_code(t_create))((void*)create_handle, &handle, create_args);

    int value = 0;
    void* handle_arg[] = { &handle };
    ((ffi_cif_func)ffi_trampoline_get_code(t_get))((void*)get_handle_value, &value, handle_arg);
    printf("Value from handle: %d\n", value); // Expected: 123

    ((ffi_cif_func)ffi_trampoline_get_code(t_destroy))((void*)destroy_handle, NULL, handle_arg);

    // 3. Clean up.
    ffi_trampoline_free(t_create);
    ffi_trampoline_free(t_destroy);
    ffi_trampoline_free(t_get);
    return 0;
}
```

### Recipe: Working with Fixed-Size Arrays

**Problem**: You need to call a function that operates on a fixed-size array, like `long long sum_array(long long arr[4]);`.

**Solution**: Use the `[N]T` syntax. While C functions will receive this as a pointer due to array-to-pointer decay, the `[N]T` signature correctly informs `infix` about the type's size and alignment, which is crucial for ABIs that pass small arrays in registers.

```c
#include <infix.h>
#include <stdio.h>

long long sum_array_elements(const long long arr[4]) { // Receives a pointer
    long long sum = 0;
    for(int i = 0; i < 4; ++i) sum += arr[i];
    return sum;
}

int main() {
    // Signature describes the conceptual type: long long(long long[4])
    const char* signature = "[4]x=>x";
    ffi_trampoline_t* trampoline = NULL;
    ffi_create_forward_trampoline_from_signature(&trampoline, signature);

    long long my_array[4] = { 10, 20, 30, 40 };
    void* args[] = { my_array }; // Pass the array directly (it decays to a pointer).
    long long result = 0;

    ((ffi_cif_func)ffi_trampoline_get_code(trampoline))((void*)sum_array_elements, &result, args);

    printf("Sum of array is: %lld\n", result); // Expected: 100

    ffi_trampoline_free(trampoline);
    return 0;
}
```

---

## Chapter 2: Handling Complex Data Structures

### Recipe: Dynamic Struct Marshalling with the Signature Parser

**Problem**: You have data from a dynamic source (e.g., a script) and need to pack it into a C `struct` layout at runtime.

**Solution**: Use `ffi_type_from_signature` to parse a signature string into a detailed `ffi_type` graph. This graph contains all the `size`, `alignment`, and member `offset` information needed to correctly write data into a C-compatible memory buffer.

```c
#include <infix.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>

typedef struct { int32_t user_id; double score; char name[16]; } UserProfile;

// This function packs ordered source values into a buffer
// based on the layout described by the signature string.
void marshal_ordered_data(void* dest_buffer, const char* signature, void** source_values) {
    ffi_type* struct_type = NULL;
    arena_t* arena = NULL;

    if (ffi_type_from_signature(&struct_type, &arena, signature) != FFI_SUCCESS) return;

    // Zero the buffer for safety.
    memset(dest_buffer, 0, struct_type->size);

    for (size_t i = 0; i < struct_type->meta.aggregate_info.num_members; ++i) {
        ffi_struct_member* member = &struct_type->meta.aggregate_info.members[i];
        printf("Marshalling member %zu to offset %zu (size %zu)\n", i, member->offset, member->type->size);
        memcpy((char*)dest_buffer + member->offset, source_values[i], member->type->size);
    }
    arena_destroy(arena);
}

int main() {
    // Our source data, in the correct order.
    int32_t id_val = 123;
    double score_val = 98.6;
    char name_val[16] = "Sanko";
    void* my_data[] = { &id_val, &score_val, &name_val };

    // A signature matching the UserProfile struct.
    const char* profile_sig = "{i,d,[16]c}";

    UserProfile profile_buffer;
    marshal_ordered_data(&profile_buffer, profile_sig, my_data);

    printf("\nResulting C struct:\n  user_id: %d\n  score:   %f\n  name:    %s\n",
           profile_buffer.user_id, profile_buffer.score, profile_buffer.name);
    return 0;
}
```

### Recipe: Small Structs Passed by Value

**Problem**: You need to call a function that takes a small `struct` that the ABI passes in registers.

**Solution**: Use the `{}` syntax. `infix` will automatically determine the correct ABI passing convention.

```c
#include <infix.h>
#include <stdio.h>

typedef struct { double x; double y; } Point;
double process_point(Point p) { return p.x + p.y; }

int main() {
    ffi_trampoline_t* trampoline = NULL;
    ffi_create_forward_trampoline_from_signature(&trampoline, "{d,d}=>d");

    Point p = { 1.5, 2.5 };
    void* args[] = { &p };
    double result = 0;
    ((ffi_cif_func)ffi_trampoline_get_code(trampoline))((void*)process_point, &result, args);

    printf("Result is: %f\n", result); // Expected: 4.0
    ffi_trampoline_free(trampoline);
    return 0;
}
```

### Recipe: Large Structs Passed by Reference

**Problem**: A function takes a struct that is too large to fit in registers.

**Solution**: The process is identical. `infix`'s ABI logic will detect that the struct is large and automatically pass it by reference.

```c
// Assume LargeStruct has size > 16 bytes.
// The signature would be, for example: "{x,x,x,x}" for a struct of 4 long longs.
// The infix C code remains the same pattern as the small struct example.
LargeStruct data = { /* ... initial values ... */ };
void* args[] = { &data };
// ... call the trampoline ...
```

### Recipe: Receiving a Struct from a Function

**Problem**: You need to call a function that *returns* a struct by value.

**Solution**: Simply use the struct signature as the return type.

```c
#include <infix.h>
#include <stdio.h>

typedef struct { double x; double y; } Point;
Point create_point() { return (Point){ 100.0, 200.0 }; }

int main() {
    ffi_trampoline_t* trampoline = NULL;
    ffi_create_forward_trampoline_from_signature(&trampoline, "=>{d,d}");

    Point result_point;
    ((ffi_cif_func)ffi_trampoline_get_code(trampoline))((void*)create_point, &result_point, NULL);

    printf("Returned point: (%f, %f)\n", result_point.x, result_point.y);
    ffi_trampoline_free(trampoline);
    return 0;
}
```

### Recipe: Working with Packed Structs via the Signature API

**Problem**: You need to call a C function that takes a packed struct.

**Solution**: Use the `p(size,align){type@offset,...}` signature syntax, providing the exact layout metadata from your C compiler.

```c
#include <infix.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#pragma pack(push, 1)
typedef struct { char a; uint64_t b; } PackedStruct; // size=9, align=1
#pragma pack(pop)

int process_packed(PackedStruct p) { return (p.a == 'X' && p.b == 0x1122334455667788ULL) ? 42 : -1; }

int main() {
    char signature[128];
    snprintf(signature, sizeof(signature), "p(%zu,%zu){c@%zu,x@%zu}=>i",
             sizeof(PackedStruct), _Alignof(PackedStruct),
             offsetof(PackedStruct, a), offsetof(PackedStruct, b));

    ffi_trampoline_t* trampoline = NULL;
    ffi_create_forward_trampoline_from_signature(&trampoline, signature);

    PackedStruct data = { 'X', 0x1122334455667788ULL };
    int result = 0;
    void* args[] = { &data };
    ((ffi_cif_func)ffi_trampoline_get_code(trampoline))((void*)process_packed, &result, args);

    printf("Packed struct result: %d\n", result); // Expected: 42
    ffi_trampoline_free(trampoline);
    return 0;
}
```

### Recipe: Working with Unions

**Problem**: You need to call a function that passes or returns a `union`.

**Solution**: Use the `<...>` syntax to describe the union. `infix` will automatically classify it based on its members for ABI compliance.

```c
#include <infix.h>
#include <stdio.h>

typedef union { int i; double d; } Number;

int process_number_as_int(Number n) { return n.i * 2; }

int main() {
    const char* signature = "<i,d>=>i"; // Signature for int(Number)
    ffi_trampoline_t* trampoline = NULL;
    ffi_create_forward_trampoline_from_signature(&trampoline, signature);

    Number num_val;
    num_val.i = 21;
    int result = 0;
    void* args[] = { &num_val };

    ((ffi_cif_func)ffi_trampoline_get_code(trampoline))((void*)process_number_as_int, &result, args);
    printf("Result: %d\n", result); // Expected: 42

    ffi_trampoline_free(trampoline);
    return 0;
}
```

### Recipe: Working with Pointers to Arrays

**Problem**: You need to call a function that takes a pointer to a fixed-size array, like `void process_matrix(int (*matrix)[4]);`. This is different from an array of pointers.

**Solution**: Use grouping parentheses `()` around the array type before adding the `*` pointer modifier. This overrides the default precedence.

| C Declaration       | Meaning                      | `infix` Signature |
| ------------------- | ---------------------------- | ----------------- |
| `int* arr[4]`       | Array of 4 `int*`            | `[4]i*`           |
| `int (*ptr_arr)[4]` | Pointer to array of 4 `int`s | `([4]i)*`         |

```c
#include <infix.h>
#include <stdio.h>

// This function expects a pointer to an array of 4 integers.
void process_matrix_row(int (*row_ptr)[4]) {
    printf("Processing row: ");
    for (int i = 0; i < 4; ++i)
        printf("%d ", (*row_ptr)[i]);
    printf("\n");
}

int main() {
    // 1. Signature for void(int(*)[4])
    const char* signature = "([4]i)*=>v"; // Take note of the grouping!
    ffi_trampoline_t* trampoline = NULL;
    ffi_create_forward_trampoline_from_signature(&trampoline, signature);

    // 2. Prepare arguments
    int matrix[2][4] = { {1, 2, 3, 4}, {5, 6, 7, 8} };
    int (*ptr_to_first_row)[4] = &matrix[0]; // This is the argument type.

    void* args[] = { &ptr_to_first_row };

    // 3. Call the function
    ((ffi_cif_func)ffi_trampoline_get_code(trampoline))((void*)process_matrix_row, NULL, args);

    ffi_trampoline_free(trampoline);
    return 0;
}
```

---

## Chapter 3: The Power of Callbacks (Reverse Calls)

### Recipe: Creating a Stateless Callback for `qsort`

**Problem**: You need to sort an array using C's `qsort`, which requires a function pointer for the comparison logic.

**Solution**: Use a reverse trampoline to create a native function pointer for your comparison handler.

```c
#include <infix.h>
#include <stdio.h>
#include <stdlib.h>

int compare_ints_handler(const void* a, const void* b) {
    int int_a = *(const int*)a; int int_b = *(const int*)b;
    if (int_a < int_b) return -1; if (int_a > int_b) return 1; return 0;
}

int main() {
    // 1. Create the reverse trampoline for the comparison function.
    ffi_reverse_trampoline_t* rt = NULL;
    ffi_create_reverse_trampoline_from_signature(&rt, "v*,v*=>i", (void*)compare_ints_handler, NULL);
    int (*comparison_func_ptr)(const void*, const void*) = ffi_reverse_trampoline_get_code(rt);

    // 2. Create the forward trampoline for qsort itself.
    // Note the function pointer signature: (v*,v*=>i)*
    ffi_trampoline_t* ft = NULL;
    ffi_create_forward_trampoline_from_signature(&ft, "v*,y,y,(v*,v*=>i)*=>v");

    // 3. Prepare arguments and call qsort.
    int numbers[] = { 5, 2, 8, 1, 9 };
    size_t num_elements = 5; size_t element_size = sizeof(int);
    void* qsort_args[] = { numbers, &num_elements, &element_size, &comparison_func_ptr };

    ((ffi_cif_func)ffi_trampoline_get_code(ft))((void*)qsort, NULL, qsort_args);

    printf("Sorted numbers: ");
    for (size_t i = 0; i < num_elements; ++i) printf("%d ", numbers[i]);
    printf("\n");

    // 4. Clean up.
    ffi_trampoline_free(ft);
    ffi_reverse_trampoline_free(rt);
    return 0;
}
```

### Recipe: Callbacks with State (Adapting to a Stateless C API)

**Problem**: A callback handler needs access to application state, but the C library API doesn't provide a `void* user_data` parameter.

**Solution**: Use a special "bridge" handler that `infix` calls. This bridge can retrieve state from the `user_data` associated with the reverse trampoline and then call your real logic. This powerful pattern adapts a stateful handler to a stateless C API.

#### The C "Library"
```c
// An iterator that takes a callback without a context parameter.
typedef void (*item_processor_t)(int item_value);
void process_list(int* items, int count, item_processor_t process_func) {
    for (int i = 0; i < count; ++i) process_func(items[i]);
}
```

#### The `infix` C Code
```c
#include <infix.h>
#include <stdio.h>

typedef struct { const char* name; int sum; } Context;

// This is the "bridge" handler that infix calls directly.
void bridge_handler(ffi_reverse_trampoline_t* context, void* ret_val, void** args) {
    // The arguments passed by the native caller are in the `args` array.
    int item_value = *(int*)args[0];

    // Retrieve our state from the user_data pointer!
    Context* ctx = (Context*)ffi_reverse_trampoline_get_user_data(context);

    // Now we can use the state.
    printf("Handler for '%s' processing %d\n", ctx->name, item_value);
    ctx->sum += item_value;
}

int main() {
    Context ctx = { "My List", 0 };

    // 1. Create a reverse trampoline, passing our context struct as user_data.
    ffi_reverse_trampoline_t* rt = NULL;
    ffi_create_reverse_trampoline_from_signature(&rt, "i=>v", (void*)bridge_handler, &ctx);
    item_processor_t processor = (item_processor_t)ffi_reverse_trampoline_get_code(rt);

    int list[] = { 10, 20, 30 };
    process_list(list, 3, processor);

    printf("Context '%s' has final sum: %d\n", ctx.name, ctx.sum); // Expected: 60

    ffi_reverse_trampoline_free(rt);
    return 0;
}
```

## Chapter 4: Advanced Techniques

### Recipe: Calling Variadic Functions like `printf`

**Problem**: You need to call a function with a variable number of arguments.

**Solution**: Provide the types for *all* arguments you intend to pass in a single call and use a semicolon (`;`) in the signature to mark where the variadic part begins.

```c
#include <infix.h>
#include <stdio.h>

int main() {
    // 1. Describe the specific signature for this call:
    //    int printf(const char* format, int, const char*);
    const char* signature = "c*;i,c*=>i";

    ffi_trampoline_t* trampoline = NULL;
    ffi_create_forward_trampoline_from_signature(&trampoline, signature);

    const char* fmt = "Number: %d, String: %s\n";
    int val = 123;
    const char* str = "test";
    void* args[] = { &fmt, &val, &str };
    int result = 0;

    ((ffi_cif_func)ffi_trampoline_get_code(trampoline))((void*)printf, &result, args);

    ffi_trampoline_free(trampoline);
    return 0;
}
```

### Recipe: Creating a Variadic Callback

**Problem**: You need to create a native function pointer for a handler that is itself variadic.

**Solution**: Your C handler will use `<stdarg.h>` to access the arguments. The `infix` signature must describe a specific, concrete instance of the variadic call you expect the C code to make.

```c
#include <infix.h>
#include <stdio.h>
#include <stdarg.h>

// Our variadic handler
void my_logger(const char* level, const char* format, ...) {
    printf("[%s] ", level);
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

// A C function that will call our logger
typedef void (*log_func_t)(const char*, const char*, ...);
void run_logger(log_func_t logger) {
    logger("INFO", "User logged in with ID %d\n", 42);
}

int main() {
    // 1. Describe the concrete signature of the call being made inside run_logger:
    //    void(const char*, const char*, int)
    const char* signature = "c*,c*;i=>v";

    ffi_reverse_trampoline_t* rt = NULL;
    ffi_create_reverse_trampoline_from_signature(&rt, signature, (void*)my_logger, NULL);

    run_logger((log_func_t)ffi_reverse_trampoline_get_code(rt));

    ffi_reverse_trampoline_free(rt);
    return 0;
}
```

### Recipe: Proving Reentrancy with Nested FFI Calls

**Problem**: You need to call a C function that takes a callback, and inside that callback handler, you need to call *another* C function using `infix`.

**Solution**: `infix` is fully reentrant. Create all necessary trampolines upfront and use them as needed.

```c
#include <infix.h>
#include <stdio.h>

// --- Mock C Library ---
static void (*g_handler)(int) = NULL;
void log_event(const char* msg) { printf("C Log: %s\n", msg); }
void register_handler(void (*h)(int)) { g_handler = h; }
void run_loop() { if (g_handler) g_handler(42); }
// --- End Mock ---

static ffi_trampoline_t* g_log_trampoline = NULL;

void my_handler(int event_code) {
    printf("Handler: Received event %d.\n", event_code);
    const char* log_msg = "Event processed.";
    void* log_args[] = { &log_msg };
    // Make a nested forward call from within the callback handler
    ((ffi_cif_func)ffi_trampoline_get_code(g_log_trampoline))((void*)log_event, NULL, log_args);
}

int main() {
    // 1. Create all trampolines upfront.
    ffi_create_forward_trampoline_from_signature(&g_log_trampoline, "c*=>v");

    ffi_reverse_trampoline_t* rt = NULL;
    ffi_create_reverse_trampoline_from_signature(&rt, "i=>v", (void*)my_handler, NULL);
    void* handler_ptr = ffi_reverse_trampoline_get_code(rt);

    ffi_trampoline_t *t_register, *t_run;
    ffi_create_forward_trampoline_from_signature(&t_register, "(i=>v)*=>v");
    ffi_create_forward_trampoline_from_signature(&t_run, "=>v");

    // 2. Execute the nested call.
    ((ffi_cif_func)ffi_trampoline_get_code(t_register))((void*)register_handler, NULL, &handler_ptr);
    ((ffi_cif_func)ffi_trampoline_get_code(t_run))((void*)run_loop, NULL, NULL);

    // 3. Cleanup.
    ffi_trampoline_free(g_log_trampoline);
    ffi_reverse_trampoline_free(rt);
    ffi_trampoline_free(t_register);
    ffi_trampoline_free(t_run);
    return 0;
}
```

### Recipe: Receiving and Calling a Function Pointer

**Problem**: You need to call a factory function that returns a pointer to another function, which you then need to call.

**Solution**: Create two trampolines: one for the factory's signature and one for the worker's signature.

```c
#include <infix.h>
#include <stdio.h>

typedef int (*math_op_t)(int, int);
int add_op(int a, int b) { return a + b; }
math_op_t get_operation(const char* name) { return add_op; }

int main() {
    // 1. Generate trampolines for BOTH signatures.
    ffi_trampoline_t *t_factory, *t_worker;
    ffi_create_forward_trampoline_from_signature(&t_factory, "c*=>(i,i=>i)*");
    ffi_create_forward_trampoline_from_signature(&t_worker, "i,i=>i");

    // 2. Call the factory to get a function pointer.
    math_op_t received_func_ptr = NULL;
    const char* op_name = "add";
    void* factory_args[] = { &op_name };
    ((ffi_cif_func)ffi_trampoline_get_code(t_factory))((void*)get_operation, &received_func_ptr, factory_args);

    // 3. Use the worker trampoline to call the returned function pointer.
    int a = 7, b = 6, result = 0;
    void* worker_args[] = { &a, &b };
    ((ffi_cif_func)ffi_trampoline_get_code(t_worker))((void*)received_func_ptr, &result, worker_args);

    printf("Result: %d\n", result); // Expected: 13

    ffi_trampoline_free(t_factory);
    ffi_trampoline_free(t_worker);
    return 0;
}
```

## Chapter 5: Interoperability with Other Languages

### The Universal Principle: The C ABI

It is possible to call a function written in Rust, Fortran, or C++ from C because of a shared standard: the **C Application Binary Interface (ABI)**. The C ABI is a set of rules for a specific CPU architecture and operating system that dictates the low-level mechanics of a function call: how arguments are passed, how return values are handled, and how function names are represented.

Nearly every compiled language provides a mechanism to expose a function using the C ABI. When they do, they create a function that is, at the machine code level, indistinguishable from one written in C.

For `infix`, this is the key insight. A C function is the same as a Rust function marked `extern "C"`. Once you have a C-compatible function pointer, the process of creating and using an `infix` trampoline is **exactly the same**, regardless of the source language.

### Part 1: The C++ Master Example

**Problem**: You need to create, use, and destroy a C++ object from a pure C environment.

**Challenge**: C++ presents two main challenges for FFI:
1.  **Name Mangling**: The C++ compiler changes function names to encode type information (e.g., `Counter::add(int)` might become `_ZN7Counter3addEi`).
2.  **The `this` Pointer**: C++ methods have a hidden first argument: the `this` pointer, which points to the object instance.

#### The Recommended Approach: `extern "C"` Wrapper

This method is **strongly recommended** as it is portable, stable, and easy to maintain. You create a simple C-style API in your C++ code that `infix` can call without issue.

##### Step 1.1: The C++ Class and Wrapper (`counter.cpp`)
```cpp
// counter.hpp
class Counter {
public:
    Counter();
    void add(int value);
    int get() const;
private:
    int count;
};

// counter.cpp
#include "counter.hpp"
Counter::Counter() : count(0) {}
void Counter::add(int value) { this->count += value; }
int Counter::get() const { return this->count; }

// The C-style wrapper API
extern "C" {
    Counter* Counter_create() { return new Counter(); }
    void Counter_destroy(Counter* c) { delete c; }
    void Counter_add(Counter* c, int value) { c->add(value); }
    int Counter_get(Counter* c) { return c->get(); }
}
```
*Compile this into a shared library: `g++ -shared -fPIC -o libcounter.so counter.cpp`*

##### Step 1.2: Using the Wrapper with `infix`
Your C code now calls the clean, predictable wrapper functions. The `void*` type (`v*` in signatures) is used as the opaque handle for the `Counter*` object.

```c
// Trampoline for Counter_create: Counter*()
ffi_create_forward_trampoline_from_signature(&t_create, "=>v*");

// Trampoline for Counter_add: void(Counter*, int)
ffi_create_forward_trampoline_from_signature(&t_add, "v*,i=>v");
```

#### The Advanced Approach: Calling Mangled Symbols Directly

> **Warning**: This method is fragile and not portable. C++ name mangling schemes differ between compilers. This should only be used as a last resort.

##### Step 2.1: Finding the Mangled Symbols

First, you must find the exact symbol names the C++ compiler generated.

*   **On Linux/macOS**: Use the `nm` utility. The `-C` flag demangles the names for readability.

    ```bash
    $ nm -C libcounter.so
    ...
    00000000000011e4 T Counter::get() const
    00000000000011c2 T Counter::add(int)
    00000000000011a0 W Counter::Counter()
    ...

    # Now, get the real (mangled) names
    $ nm libcounter.so
    ...
    00000000000011e4 T _ZNK7Counter3getEv  <-- get() const
    00000000000011c2 T _ZN7Counter3addEi    <-- add(int)
    00000000000011a0 W _ZN7CounterC1Ev    <-- Constructor
    ...
    ```

*   **On Windows**: Use `dumpbin` from a Visual Studio command prompt.

    ```bash
    > dumpbin /SYMBOLS libcounter.dll | findstr "Counter"
    ... ??0Counter@@QEAA@XZ            ; Counter::Counter() (Constructor)
    ... ?add@Counter@@QEAAXH@Z         ; Counter::add(int)
    ... ?get@Counter@@QEBAHXZ          ; Counter::get(void)
    ```
##### Step 2.2: Calling the Mangled Symbols with `infix`
The key is to treat the hidden `this` pointer as the **first argument** to every method call.

```c
// C++ method: void Counter::add(int value);
// FFI signature must be: void(Counter* this, int value) => "v*,i=>v"

void* counter_instance = malloc(sizeof(int)); // Must match sizeof(Counter)
int value_to_add = 42;
void* add_arg_vals[] = { &counter_instance, &value_to_add };

// Call the mangled symbol for "add"
cif_add(mangled_add_ptr, NULL, add_arg_vals);
```

### Part 2: The Pattern for Other Compiled Languages

The following examples all demonstrate how to export a simple `int add(int, int)` function from a shared library. Notice how the infix C code is nearly identical in every case, highlighting the power of the C ABI as a universal interface.

#### Rust

**Discussion**: Rust has excellent, first-class support for C interoperability. The `extern "C"` keyword tells the compiler to use the C ABI, and the `#[no_mangle]` attribute prevents it from changing the function's name.

##### Rust Code (`librust_math.rs`)
```rust
#[no_mangle]
pub extern "C" fn rust_add(a: i32, b: i32) -> i32 {
    a + b
}
```
*Compile with: `rustc --crate-type cdylib librust_math.rs`*

##### infix C Code (`main_rust.c`)
```c
#include <infix.h>
#include <stdio.h>
#include <dlfcn.h>

int main() {
    void* lib = dlopen("./librust_math.so", RTLD_LAZY);
    int (*rust_add)(int, int) = dlsym(lib, "rust_add");

    ffi_type* s32_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32);
    ffi_type* arg_types[] = { s32_type, s32_type };
    ffi_trampoline_t* trampoline = NULL;
    generate_forward_trampoline(&trampoline, s32_type, arg_types, 2, 2);

    int a = 50, b = 50;
    void* args[] = { &a, &b };
    int result = 0;

    ((ffi_cif_func)ffi_trampoline_get_code(trampoline))((void*)rust_add, &result, args);

    printf("Result from Rust: %d\n", result); // Expected: 100

    ffi_trampoline_free(trampoline);
    dlclose(lib);
    return 0;
}
```

#### Fortran

**Discussion**: Modern Fortran (2003+) can interoperate with C using the standard `iso_c_binding` module. The `bind(C)` attribute is the key to creating a C-compatible function. We must also explicitly tell it which arguments are passed by value, as Fortran's default is to pass by reference.

##### Fortran Code (`libfortran_math.f90`)
```fortran
function fortran_add(a, b) result(c) bind(C, name='fortran_add')
    use iso_c_binding
    integer(c_int), value :: a, b
    integer(c_int) :: c
    c = a + b
end function fortran_add
```
*Compile with: `gfortran -shared -fPIC -o libfortran_math.so libfortran_math.f90`*

##### infix C Code (`main_fortran.c`)
```c
#include <infix.h>
#include <stdio.h>
#include <dlfcn.h>

int main() {
    void* lib = dlopen("./libfortran_math.so", RTLD_LAZY);
    int (*fortran_add)(int, int) = dlsym(lib, "fortran_add");

    // The infix code is identical to the Rust example!
    ffi_type* s32_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32);
    ffi_type* arg_types[] = { s32_type, s32_type };
    ffi_trampoline_t* trampoline = NULL;
    generate_forward_trampoline(&trampoline, s32_type, arg_types, 2, 2);

    int a = 20, b = 22;
    void* args[] = { &a, &b };
    int result = 0;

    ((ffi_cif_func)ffi_trampoline_get_code(trampoline))((void*)fortran_add, &result, args);

    printf("Result from Fortran: %d\n", result); // Expected: 42

    ffi_trampoline_free(trampoline);
    dlclose(lib);
    return 0;
}
```

#### Zig

**Discussion**: Zig is designed for seamless C integration. The `export` keyword is all that's needed to create a C-compatible function in a shared library.

##### Zig Code (`libzig_math.zig`)
```zig
const std = @import("std");

export fn zig_add(a: c_int, b: c_int) c_int {
    return a + b;
}
```
*Compile with: `zig build-lib -dynamic libzig_math.zig`*

##### infix C Code (`main_zig.c`)
The C code would be identical to the previous examples, just loading `libzig_math.so` and calling the `zig_add` symbol.

#### Go

**Discussion**: Go can export functions to C using a special build mode and `cgo`. This involves a specific comment (`//export`) above the function.

##### Go Code (`libgo_math.go`)
```go
package main

import "C"

//export go_add
func go_add(a C.int, b C.int) C.int {
    return a + b
}

func main() {} // Required for the build, but not used.
```
*Compile with: `go build -buildmode=c-shared -o libgo_math.so libgo_math.go`*

##### infix C Code (`main_go.c`)
The C code would be identical to the previous examples, just loading `libgo_math.so` and calling the `go_add` symbol.

#### Swift

**Discussion**: Swift can export functions to C using the `@_cdecl` attribute, which makes them available via the C ABI.

##### Swift Code (`libswift_math.swift`)
```swift
import Foundation

@_cdecl("swift_add")
public func swift_add(a: CInt, b: CInt) -> CInt {
    return a + b
}
```
*Compile with: `swiftc -emit-library libswift_math.swift -o libswift_math.so`*

##### infix C Code (`main_swift.c`)
The C code would be identical to the previous examples, just loading `libswift_math.so` and calling the `swift_add` symbol.

#### D (dlang)

**Discussion**: The D language provides `extern (C)` to apply C linkage and calling conventions.

##### D Code (`libd_math.d`)
```d
extern (C) int d_add(int a, int b) {
    return a + b;
}
```
*Compile with: `dmd -shared -fPIC -of=libd_math.so libd_math.d`*

##### infix C Code (`main_d.c`)
The C code would be identical to the previous examples, just loading `libd_math.so` and calling the `d_add` symbol.

#### Assembly (NASM)

**Discussion**: This is the ultimate example. Assembly doesn't *use* an ABI; it *implements* it. Here we write an `add` function for the System V AMD64 ABI directly.

##### NASM Code (`libasm_math.asm`)
```nasm
section .text
global asm_add

; int asm_add(int edi, int esi)
asm_add:
    mov eax, edi    ; Move first argument (edi) into eax
    add eax, esi    ; Add second argument (esi) to eax
    ret             ; Return value is in eax
```
*Compile with: `nasm -f elf64 -o libasm_math.o libasm_math.asm && gcc -shared -o libasm_math.so libasm_math.o`*

##### infix C Code (`main_asm.c`)
The C code would be identical to the previous examples, just loading `libasm_math.so` and calling the `asm_add` symbol. This demonstrates that infix is simply generating the machine code necessary to talk to any function that adheres to the platform's C ABI, no matter how it was created.

---

## Chapter 6: Calling System Libraries

### Recipe (Windows): Displaying a `MessageBox`

**Problem**: You want to display a native GUI message box on Windows.

**Solution**: Load `User32.dll` and call `MessageBoxW`. Windows types like `HWND` and `LPCWSTR` are pointers, and `UINT` is a 32-bit integer.

```c
#if defined(_WIN32)
#include <infix.h>
#include <stdio.h>
#include <windows.h>

int main() {
    HMODULE user32 = LoadLibraryA("user32.dll");
    void* MessageBoxW_ptr = (void*)GetProcAddress(user32, "MessageBoxW");

    // Signature: int(HWND, LPCWSTR, LPCWSTR, UINT)
    const char* signature = "v*,v*,v*,j=>i"; // Using v* for handles, j for UINT
    ffi_trampoline_t* trampoline = NULL;
    ffi_create_forward_trampoline_from_signature(&trampoline, signature);

    // Prepare arguments. Windows uses UTF-16 for wide strings (L"").
    HWND hwnd = NULL;
    const wchar_t* text = L"This is a message from infix!";
    const wchar_t* caption = L"infix FFI Test";
    UINT type = MB_OK | MB_ICONINFORMATION;

    void* args[] = { &hwnd, &text, &caption, &type };
    int result = 0;
    ((ffi_cif_func)ffi_trampoline_get_code(trampoline))((void*)MessageBoxW_ptr, &result, args);

    ffi_trampoline_free(trampoline);
    FreeLibrary(user32);
    return 0;
}
#else
int main() { return 0; }
#endif
```

### Recipe (macOS): Interacting with CoreFoundation Objects

**Problem**: You want to use a native macOS framework like CoreFoundation.

**Solution**: CoreFoundation uses opaque pointers (`CFStringRef`, etc.) which are treated as `v*` in `infix`.

```c
#if defined(__APPLE__)
#include <infix.h>
#include <stdio.h>
#include <dlfcn.h>

typedef const void* CFStringRef;
typedef long CFIndex; // On macOS, CFIndex is a long (64-bit)

int main() {
    void* cf = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", RTLD_LAZY);
    void* CFStringCreateWithCString = dlsym(cf, "CFStringCreateWithCString");
    void* CFStringGetLength = dlsym(cf, "CFStringGetLength");
    void* CFRelease = dlsym(cf, "CFRelease");

    ffi_trampoline_t *t_create, *t_getlen, *t_release;
    ffi_create_forward_trampoline_from_signature(&t_create, "v*,c*,i=>v*");
    ffi_create_forward_trampoline_from_signature(&t_getlen, "v*=>l");
    ffi_create_forward_trampoline_from_signature(&t_release, "v*=>v");

    const char* my_str = "Hello from macOS!";
    int encoding = 0x0600; // kCFStringEncodingUTF8
    void* create_args[] = { NULL, &my_str, &encoding };
    CFStringRef cf_str = NULL;
    ((ffi_cif_func)ffi_trampoline_get_code(t_create))(CFStringCreateWithCString, &cf_str, create_args);

    CFIndex length = 0;
    void* getlen_args[] = { &cf_str };
    ((ffi_cif_func)ffi_trampoline_get_code(t_getlen))(CFStringGetLength, &length, getlen_args);
    printf("String length is: %ld\n", length);

    ((ffi_cif_func)ffi_trampoline_get_code(t_release))(CFRelease, NULL, getlen_args);

    ffi_trampoline_free(t_create);
    ffi_trampoline_free(t_getlen);
    ffi_trampoline_free(t_release);
    dlclose(cf);
    return 0;
}
#else
int main() { return 0; }
#endif
```

### Recipe (Linux/POSIX): Getting System Information

**Problem**: You need to get the machine's hostname and query the math library.

**Solution**: Load `libc` for `gethostname` and `libm` for `pow`. Note that on 64-bit Linux, `size_t` is a 64-bit unsigned integer (`y`).

```c
#if defined(__linux__)
#include <infix.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>

int main() {
    void* libc = dlopen("libc.so.6", RTLD_LAZY);
    void* gethostname_ptr = dlsym(libc, "gethostname");
    void* libm = dlopen("libm.so.6", RTLD_LAZY);
    void* pow_ptr = dlsym(libm, "pow");

    ffi_trampoline_t *t_hostname, *t_pow;
    ffi_create_forward_trampoline_from_signature(&t_hostname, "c*,y=>i");
    ffi_create_forward_trampoline_from_signature(&t_pow, "d,d=>d");

    // Call gethostname
    char hostname_buf[256] = {0};
    size_t len = sizeof(hostname_buf);
    int result = 0;
    void* hostname_args[] = { hostname_buf, &len };
    ((ffi_cif_func)ffi_trampoline_get_code(t_hostname))(gethostname_ptr, &result, hostname_args);
    if (result == 0) printf("Linux Hostname: %s\n", hostname_buf);

    // Call pow
    double base = 2.0, exp = 10.0, pow_result = 0.0;
    void* pow_args[] = { &base, &exp };
    ((ffi_cif_func)ffi_trampoline_get_code(t_pow))(pow_ptr, &pow_result, pow_args);
    printf("2^10 = %f\n", pow_result); // Expected: 1024.0

    ffi_trampoline_free(t_hostname);
    ffi_trampoline_free(t_pow);
    dlclose(libc);
    dlclose(libm);
    return 0;
}
#else
int main() { return 0; }
#endif
```

## Chapter 7: Memory Management & Performance

**Discussion**: `infix` is designed for high performance, but this requires understanding the difference between the one-time cost of **generating** a trampoline and the per-call overhead of **invoking** it.

### Understanding Generation vs. Call-Time Overhead

1.  **Generation Time**: This is the "setup" cost incurred when you call a function like `ffi_create_forward_trampoline_from_signature`. `infix` analyzes the signature, calculates the call frame layout, allocates executable memory, and JIT-compiles the machine code. This is the "expensive" part of the process.

2.  **Call Time**: This is the recurring cost of invoking a function through an already-created trampoline. This overhead is extremely low—typically measured in single-digit nanoseconds—as it's just a few extra instructions before the final native `call`.

### Best Practice: Caching Trampolines

Given the difference, the most important performance pattern is to **cache trampolines**. Generate them once during an initialization phase and reuse them for the lifetime of your application.

**Rule**: **NEVER** generate a new trampoline for the same function signature inside a hot loop.

```c
// Anti-pattern: DO NOT DO THIS!
for (int i = 0; i < 1000000; ++i) {
    ffi_trampoline_t* t;
    // VERY SLOW: Generating a new trampoline on every iteration.
    ffi_create_forward_trampoline_from_signature(&t, "i,i=>i");
    cif_func(target, &result, args);
    ffi_trampoline_free(t);
}

// Correct Pattern: Generate once, use many times.
ffi_trampoline_t* t;
ffi_create_forward_trampoline_from_signature(&t, "i,i=>i");
ffi_cif_func cif_func = (ffi_cif_func)ffi_trampoline_get_code(t);

for (int i = 0; i < 1000000; ++i) {
    // VERY FAST: Re-using the same highly-optimized trampoline.
    cif_func(target, &result, args);
}

ffi_trampoline_free(t);
```
By amortizing the one-time generation cost over millions of calls, the FFI overhead becomes negligible.

---

## Chapter 8: Common Pitfalls & Troubleshooting

### Mistake: Passing a Value Instead of a Pointer in `args[]`

*   **Symptom**: Immediate crash (segmentation fault) or garbage data.
*   **Explanation**: The `args` array must contain **pointers to** your argument values, not the values themselves.
*   **Solution**: Always use the address-of operator (`&`).

```c
// WRONG:
int my_int = 42;
void* args[] = { (void*)(intptr_t)my_int }; // Crashes!

// CORRECT:
int my_int = 42;
void* args[] = { &my_int };
```

### Mistake: `ffi_type` Mismatch

*   **Symptom**: Silent data corruption or a crash much later in execution.
*   **Explanation**: The `ffi_type` you describe must *exactly* match the C type's size and alignment. A common error is mismatching the `long` type, which is 32 bits on 64-bit Windows but 64 bits on 64-bit Linux.
*   **Solution**: Use the fixed-width types from `<stdint.h>` (like `int64_t`) and their corresponding `infix` types (`x` for `int64_t`) whenever possible.

### Mistake: Forgetting to Free Dynamic `ffi_type` Objects

*   **Symptom**: Memory leaks reported by tools like Valgrind or AddressSanitizer.
*   **Explanation**: Types created with `ffi_type_create_struct`, `_union`, or `_array` are dynamically allocated and must be freed with `ffi_type_destroy`. Primitive and pointer types are static and should not be freed.
*   **Solution**: Call `ffi_type_destroy` on any `ffi_type*` created for a struct, union, or array after all trampolines using it have been created. The function safely ignores static types.

---

## Chapter 9: Building Language Bindings

**Discussion**: `infix` is an ideal engine for creating a "language binding"—a library that allows a high-level language like Python, Ruby, or Lua to call C functions. The binding provides the crucial "glue" to the high-level language's runtime.

### The Four Pillars of a Language Binding

A robust language binding built on `infix` must solve four main challenges.

#### 1. Type Mapping -> Signature String Generation

Instead of building complex C `ffi_type` objects, the binding's primary job is to **generate a signature string** from the high-level language's type information. This is a much simpler string manipulation task.

**Conceptual Python Binding Code:**
```python
# A conceptual function in a Python binding
def _get_signature_string_from_ctypes(restype, argtypes):
    type_map = { ctypes.c_int: 'i', ctypes.c_double: 'd', ctypes.c_void_p: 'v*' }

    arg_parts = [_map_type_to_sig(t) for t in argtypes] # _map_type_to_sig is recursive
    ret_part = _map_type_to_sig(restype)

    return f"{','.join(arg_parts)}=>{ret_part}"
```

#### 2. Trampoline Caching

Generating a trampoline is a one-time setup cost. The binding **must** implement a global, persistent cache for trampolines, using the signature string as the key.

**Conceptual C++ Binding Code:**
```cpp
#include <map>
#include <string>
#include "infix.h"

// A global cache mapping signature strings to trampolines.
static std::map<std::string, ffi_trampoline_t*> g_trampoline_cache;

ffi_trampoline_t* get_or_create_trampoline(const char* signature) {
    if (g_trampoline_cache.count(signature)) {
        return g_trampoline_cache[signature];
    }
    ffi_trampoline_t* new_trampoline = NULL;
    if (ffi_create_forward_trampoline_from_signature(&new_trampoline, signature) == FFI_SUCCESS) {
        g_trampoline_cache[signature] = new_trampoline;
    }
    return new_trampoline;
}
```

#### 3. Managing Memory & Object Lifetimes

This is often the hardest part of FFI. The high-level language has a garbage collector (GC), but C does not. The binding must act as a bridge.

*   **For Forward Calls (HLL -> C)**: When passing an object like a string to C, the binding must **hold a reference** to the high-level object for the duration of the C call to prevent the GC from collecting its memory.
*   **For Reverse Calls (C -> HLL)**: When a high-level function is passed to C as a callback, the binding must store a **handle to the HLL function object** in the `user_data` field of the reverse trampoline. When the trampoline is freed, the binding must release its reference, allowing the GC to collect it.

#### 4. Implementing the Callback Bridge

When a C library invokes a reverse trampoline, the JIT-compiled stub calls a C handler. This "bridge" handler must then transfer control back to the high-level language's runtime.

**Conceptual Python Callback Bridge:**
```c
#include <Python.h> // Example for Python

// This C function is the handler given to infix.
void python_callback_bridge(ffi_reverse_trampoline_t* context, void* ret_ptr, void** args) {
    PyGILState_STATE gstate = PyGILState_Ensure(); // 1. Acquire the GIL.
    PyObject* py_callback = (PyObject*)ffi_reverse_trampoline_get_user_data(context); // 2. Get Python func.
    PyObject* py_args = convert_c_args_to_python_tuple(context, args); // 3. Convert args.
    PyObject* py_result = PyObject_CallObject(py_callback, py_args); // 4. Call Python func.

    if (py_result != NULL) {
        convert_python_result_to_c(py_result, context->return_type, ret_ptr); // 5. Convert return.
        Py_DECREF(py_result);
    } else {
        PyErr_Print(); // Handle exceptions.
    }

    Py_DECREF(py_args);
    PyGILState_Release(gstate); // 6. Release the GIL.
}
```

---

# License and Legal

Copyright (c) 2025 Sanko Robinson

This documentation is licensed under the Creative Commons Attribution 4.0 International License (CC BY 4.0). You are free to share and adapt this material for any purpose, provided you give appropriate credit.

For the full license text, see the [LICENSE-CC](/LICENSE-CC) file or visit [https://creativecommons.org/licenses/by/4.0/](https://creativecommons.org/licenses/by/4.0/).
