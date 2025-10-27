# The infix FFI Cookbook

This guide provides practical, real-world examples to help you solve common FFI problems and leverage the full power of the `infix` library. Where the `README.md` covers concepts, this cookbook provides the code.

> **Note:** For a complete reference on the string format used in these examples (e.g., `"int"`, `"{double, double}"`, `"*char"`), please see the **[Signature Language Reference](signatures.md)**.

## Table of Contents

   * [Chapter 1: The Basics (Forward Calls)](#chapter-1-the-basics-forward-calls)
      + [Recipe: Calling a Simple C Function](#recipe-calling-a-simple-c-function)
      + [Recipe: Passing and Receiving Pointers](#recipe-passing-and-receiving-pointers)
      + [Recipe: Working with "Out" Parameters](#recipe-working-with-out-parameters)
      + [Recipe: Working with Opaque Pointers (Incomplete Types)](#recipe-working-with-opaque-pointers-incomplete-types)
   * [Chapter 2: Handling Complex Data Structures](#chapter-2-handling-complex-data-structures)
      + [Recipe: Small Structs Passed by Value](#recipe-small-structs-passed-by-value)
      + [Recipe: Receiving a Struct from a Function](#recipe-receiving-a-struct-from-a-function)
      + [Recipe: Large Structs Passed by Reference](#recipe-large-structs-passed-by-reference)
      + [Recipe: Working with Packed Structs](#recipe-working-with-packed-structs)
      + [Recipe: Working with Structs that Contain Bitfields](#recipe-working-with-structs-that-contain-bitfields)
      + [Recipe: Working with Unions](#recipe-working-with-unions)
      + [Recipe: Working with Fixed-Size Arrays](#recipe-working-with-fixed-size-arrays)
      + [Recipe: Advanced Named Types (Recursive & Forward-Declared)](#recipe-advanced-named-types-recursive--forward-declared)
      + [Recipe: Working with Complex Numbers](#recipe-working-with-complex-numbers)
      + [Recipe: Working with SIMD Vectors](#recipe-working-with-simd-vectors)
      + [Recipe: Working with Enums](#recipe-working-with-enums)
   * [Chapter 3: The Power of Callbacks (Reverse Calls)](#chapter-3-the-power-of-callbacks-reverse-calls)
      + [Recipe: Creating a Type-Safe Callback for `qsort`](#recipe-creating-a-type-safe-callback-for-qsort)
      + [Recipe: Creating a Stateful Callback](#recipe-creating-a-stateful-callback)
   * [Chapter 4: Advanced Techniques](#chapter-4-advanced-techniques)
      + [Recipe: Calling Variadic Functions like `printf`](#recipe-calling-variadic-functions-like-printf)
      + [Recipe: Receiving and Calling a Function Pointer](#recipe-receiving-and-calling-a-function-pointer)
      + [Recipe: Calling a Function Pointer from a Struct (V-Table Emulation)](#recipe-calling-a-function-pointer-from-a-struct-v-table-emulation)
      + [Recipe: Handling `longdouble`](#recipe-handling-longdouble)
      + [Recipe: Proving Reentrancy with Nested FFI Calls](#recipe-proving-reentrancy-with-nested-ffi-calls)
      + [Recipe: Proving Thread Safety](#recipe-proving-thread-safety)
   * [Chapter 5: Interoperability with Other Languages](#chapter-5-interoperability-with-other-languages)
      + [The Universal Principle: The C ABI](#the-universal-principle-the-c-abi)
      + [Recipe: Interfacing with a C++ Class (Directly)](#recipe-interfacing-with-a-c-class-directly)
      + [Recipe: Interfacing with C++ Templates](#recipe-interfacing-with-c-templates)
      + [The Pattern for Other Compiled Languages](#the-pattern-for-other-compiled-languages)
         - [Rust](#rust)
         - [Zig](#zig)
         - [Go](#go)
         - [Swift](#swift)
         - [Dlang](#dlang)
         - [Fortran](#fortran)
         - [Assembly](#assembly)
   * [Chapter 6: Dynamic Libraries & System Calls](#chapter-6-dynamic-libraries--system-calls)
      + [Recipe: Calling Native System Libraries without Linking](#recipe-calling-native-system-libraries-without-linking)
      + [Recipe: Reading and Writing Global Variables](#recipe-reading-and-writing-global-variables)
         - [Example 1: Simple Integer Variable](#example-1-simple-integer-variable)
         - [Example 2: Aggregate (Struct) Variable](#example-2-aggregate-struct-variable)
      + [Recipe: Handling Library Dependencies](#recipe-handling-library-dependencies)
   * [Chapter 7: Introspection for Data Marshalling](#chapter-7-introspection-for-data-marshalling)
      + [Recipe: Dynamic Struct Marshalling with the Signature Parser](#recipe-dynamic-struct-marshalling-with-the-signature-parser)
      + [Recipe: Building a Signature String at Runtime](#recipe-building-a-signature-string-at-runtime)
      + [Recipe: Introspecting a Trampoline for a Wrapper](#recipe-introspecting-a-trampoline-for-a-wrapper)
   * [Chapter 8: Performance & Memory Management](#chapter-8-performance--memory-management)
      + [Best Practice: Caching Trampolines](#best-practice-caching-trampolines)
      + [Recipe: Using a Custom Arena for a Group of Types](#recipe-using-a-custom-arena-for-a-group-of-types)
      + [Recipe: The Full Manual API Lifecycle (Types to Trampoline)](#recipe-the-full-manual-api-lifecycle-types-to-trampoline)
      + [Recipe: Using Custom Memory Allocators](#recipe-using-custom-memory-allocators)
      + [Recipe: Building a Dynamic Call Frame with an Arena](#recipe-building-a-dynamic-call-frame-with-an-arena)
         - [How It Works & Why It's Better](#how-it-works--why-its-better)
         - [Advanced Optimization: Arena Resetting for Hot Loops](#advanced-optimization-arena-resetting-for-hot-loops)
   * [Chapter 9: Common Pitfalls & Troubleshooting](#chapter-9-common-pitfalls--troubleshooting)
      + [Recipe: Advanced Error Reporting for the Parser](#recipe-advanced-error-reporting-for-the-parser)
      + [Mistake: Passing a Value Instead of a Pointer in `args[]`](#mistake-passing-a-value-instead-of-a-pointer-in-args)
      + [Mistake: `infix` Signature Mismatch](#mistake-infix-signature-mismatch)
      + [Pitfall: Function Pointer Syntax](#pitfall-function-pointer-syntax)
   * [Chapter 10: A Comparative Look: `infix` vs. `libffi` and `dyncall`](#chapter-10-a-comparative-look-infix-vs-libffi-and-dyncall)
      + [Scenario 1: Calling a Simple Function](#scenario-1-calling-a-simple-function)
         - [The `dyncall` Approach](#the-dyncall-approach)
         - [The `libffi` Approach](#the-libffi-approach)
         - [The `infix` Approach](#the-infix-approach)
      + [Scenario 2: Calling a Function with a Struct](#scenario-2-calling-a-function-with-a-struct)
         - [The `dyncall` Approach](#the-dyncall-approach-1)
         - [The `libffi` Approach](#the-libffi-approach-1)
         - [The `infix` Approach](#the-infix-approach-1)
      + [Scenario 3: Creating a Callback](#scenario-3-creating-a-callback)
         - [The `dyncall` Approach](#the-dyncall-approach-2)
         - [The `libffi` Approach](#the-libffi-approach-2)
         - [The `infix` Approach](#the-infix-approach-2)
      + [Analysis and Takeaways](#analysis-and-takeaways)
   * [Chapter 11: Building Language Bindings](#chapter-11-building-language-bindings)
      + [The Four Pillars of a Language Binding](#the-four-pillars-of-a-language-binding)
      + [Recipe: Porting a Python Binding from `dyncall` to `infix`](#recipe-porting-a-python-binding-from-dyncall-to-infix)

---

## Chapter 1: The Basics (Forward Calls)

### Recipe: Calling a Simple C Function

**Problem**: You want to call a standard C function, like `atan2` from the math library.

**Solution**: Describe the function's signature, prepare pointers to your arguments, and invoke the function through a generated trampoline. An "unbound" trampoline is ideal when you want to call multiple functions that share the same signature.

```c
#include <infix/infix.h>
#include <math.h>
#include <stdio.h>

void recipe_simple_forward_call() {
    // 1. Describe the signature: double atan2(double y, double x);
    const char* signature = "(double, double) -> double";

    // 2. Create an unbound trampoline. The function to call is not specified yet.
    infix_forward_t* trampoline = NULL;
    infix_forward_create_unbound(&trampoline, signature, NULL);

    // 3. Get the callable function pointer.
    infix_unbound_cif_func cif = infix_forward_get_unbound_code(trampoline);

    // 4. Prepare arguments. The args array must hold *pointers* to the values.
    double y = 1.0, x = 1.0;
    void* args[] = { &y, &x };
    double result;

    // 5. Invoke the call, passing the target function `atan2` as the first argument.
    cif((void*)atan2, &result, args);

    printf("atan2(1.0, 1.0) = %f (PI/4)\n", result);

    // 6. Clean up.
    infix_forward_destroy(trampoline);
}
```

### Recipe: Passing and Receiving Pointers

**Problem**: You need to call a C function that takes a pointer as an argument and returns a pointer, like `strchr`.

**Solution**: Use the `*` prefix for pointer types. The value in the `args` array for a pointer argument is the address of your pointer variable.

```c
#include <infix/infix.h>
#include <string.h>
#include <stdio.h>

void recipe_pointer_args_and_return() {
    // Signature for: const char* strchr(const char* s, int c);
    const char* signature = "(*char, int) -> *char";
    infix_forward_t* trampoline = NULL;
    infix_forward_create(&trampoline, signature, (void*)strchr, NULL);
    infix_cif_func cif = infix_forward_get_code(trampoline);

    const char* haystack = "hello-world";
    int needle = '-';
    void* args[] = { &haystack, &needle };
    const char* result_ptr = NULL;

    cif(&result_ptr, args);

    if (result_ptr) {
        printf("strchr found: '%s'\n", result_ptr); // Expected: "-world"
    }
    infix_forward_destroy(trampoline);
}
```

### Recipe: Working with "Out" Parameters

**Problem**: You need to call a C function that doesn't use its return value for its primary output. Instead, it takes a pointer to a variable and writes the result into it. This is a very common pattern for functions that need to return multiple values or an error code.

**Solution**: The signature is straightforward. The "out" parameter is simply a pointer type (`*<type>`). In your calling code, you create a local variable and pass its address in the `args` array.

```c
// Native C function to be called:
// bool get_user_stats(int user_id, int* out_posts, double* out_score);
bool get_user_stats(int user_id, int* out_posts, double* out_score) {
    if (user_id == 123) {
        if(out_posts) *out_posts = 50;
        if(out_score) *out_score = 99.8;
        return true;
    }
    return false;
}

void recipe_out_parameters() {
    const char* signature = "(int, *int, *double) -> bool";
    infix_forward_t* t = NULL;
    infix_forward_create(&t, signature, (void*)get_user_stats, NULL);

    int user_id = 123;
    // These are our "out" variables. They will be modified by the C function.
    int post_count = 0;
    double score = 0.0;
    bool success;

    // The args array contains pointers to our local variables.
    void* args[] = { &user_id, &post_count, &score };

    infix_forward_get_code(t)(&success, args);

    if (success) {
        printf("User stats: Posts=%d, Score=%.1f\n", post_count, score); // Expected: 50, 99.8
    }

    infix_forward_destroy(t);
}
```

### Recipe: Working with Opaque Pointers (Incomplete Types)

**Problem**: You need to interact with a C library that uses opaque pointers or handles (e.g., `FILE*`, `sqlite3*`) where the internal structure is hidden.

**Solution**: Use the `*void` signature. This is the canonical representation for any generic handle. Using a registry to create a type alias like `@FileHandle = *void;` can make your signatures more readable.

```c
#include <infix/infix.h>
#include <stdio.h>

void recipe_opaque_pointers() {
    infix_registry_t* reg = infix_registry_create();
    infix_register_types(reg, "@FileHandle = *void;");

    infix_forward_t *t_fopen, *t_fputs, *t_fclose;
    infix_forward_create(&t_fopen, "(*char, *char) -> @FileHandle", (void*)fopen, reg);
    infix_forward_create(&t_fputs, "(*char, @FileHandle) -> int", (void*)fputs, reg);
    infix_forward_create(&t_fclose, "(@FileHandle) -> int", (void*)fclose, reg);

    void* file_handle = NULL; // This will hold our opaque FILE*
    const char* filename = "test.txt";
    const char* mode = "w";
    void* fopen_args[] = { &filename, &mode };

    infix_forward_get_code(t_fopen)(&file_handle, fopen_args);

    if (file_handle) {
        const char* content = "Written by infix!";
        void* fputs_args[] = { &content, &file_handle };
        int result;
        infix_forward_get_code(t_fputs)(&result, fputs_args);
        infix_forward_get_code(t_fclose)(&result, &file_handle);
        printf("Successfully wrote to test.txt\n");
    }

    infix_forward_destroy(t_fopen);
    infix_forward_destroy(t_fputs);
    infix_forward_destroy(t_fclose);
    infix_registry_destroy(reg);
}
```

---

## Chapter 2: Handling Complex Data Structures

```c
// Common C struct used in this chapter's examples
typedef struct { double x, y; } Point;
```

### Recipe: Small Structs Passed by Value
**Problem**: You need to call a function that takes a small `struct` that the ABI passes in registers.
**Solution**: Use the struct syntax `({...})`. `infix` will automatically determine the correct ABI passing convention for the target platform.

```c
Point move_point(Point p, double dx) { p.x += dx; return p; }

void recipe_pass_struct_by_value() {
    const char* signature = "({double, double}, double) -> {double, double}";
    infix_forward_t* trampoline = NULL;
    infix_forward_create(&trampoline, signature, (void*)move_point, NULL);

    Point start = { 10.0, 20.0 };
    double delta_x = 5.5;
    void* args[] = { &start, &delta_x };
    Point end;

    infix_forward_get_code(trampoline)(&end, args);
    printf("Moved point has x = %f\n", end.x); // Should be 15.5

    infix_forward_destroy(trampoline);
}
```

### Recipe: Receiving a Struct from a Function

**Problem**: You need to call a function that *returns* a struct by value.

**Solution**: `infix` handles the ABI details, whether the struct is returned in registers or via a hidden pointer passed by the caller.

```c
Point make_point(double x, double y) { return (Point){x, y}; }

void recipe_return_struct() {
    const char* signature = "(double, double) -> {double, double}";
    infix_forward_t* trampoline = NULL;
    infix_forward_create(&trampoline, signature, (void*)make_point, NULL);

    double x = 100.0, y = 200.0;
    void* args[] = { &x, &y };
    Point result;

    infix_forward_get_code(trampoline)(&result, args);
    printf("Received point: {x=%.1f, y=%.1f}\n", result.x, result.y);

    infix_forward_destroy(trampoline);
}
```

### Recipe: Large Structs Passed by Reference

**Problem**: A function takes a struct that is too large to fit in registers.

**Solution**: The process is identical to the small struct example. `infix`'s ABI logic will detect that the struct is large and automatically pass it by reference (the standard C ABI rule).

```c
typedef struct { int data[8]; } LargeStruct;
int get_first_element(LargeStruct s) { return s.data[0]; }

void recipe_large_struct() {
    const char* signature = "({[8:int]}) -> int";
    infix_forward_t* t = NULL;
    infix_forward_create(&t, signature, (void*)get_first_element, NULL);

    LargeStruct my_struct = { {123, -1, -1, -1, -1, -1, -1, -1} };
    void* args[] = { &my_struct };
    int result;

    infix_forward_get_code(t)(&result, args);
    printf("First element of large struct: %d\n", result); // Should be 123

    infix_forward_destroy(t);
}
```

### Recipe: Working with Packed Structs

**Problem**: You need to call a function that takes a `__attribute__((packed))` struct.

**Solution**: Use the `!{...}` syntax for 1-byte alignment, or `!N:{...}` to specify a maximum alignment of `N` bytes.

```c
#pragma pack(push, 1)
typedef struct { char a; uint64_t b; } Packed; // Total size is 9 bytes
#pragma pack(pop)

int process_packed(Packed p) { return (p.a == 'X' && p.b == 0x1122334455667788ULL) ? 42 : -1; }

void recipe_packed_struct() {
    const char* signature = "(!{char, uint64}) -> int";
    infix_forward_t* t = NULL;
    infix_forward_create(&t, signature, (void*)process_packed, NULL);

    Packed p = {'X', 0x1122334455667788ULL};
    int result = 0;
    void* args[] = {&p};

    infix_forward_get_code(t)(&result, args);
    printf("Packed struct result: %d\n", result);  // Expected: 42
    infix_forward_destroy(t);
}
```

### Recipe: Working with Structs that Contain Bitfields

**Problem**: You need to interact with a C struct that uses bitfields. `infix`'s signature language has no syntax for bitfields because their memory layout is implementation-defined and not portable.

**Solution**: Treat the underlying integer that holds the bitfields as a single member in your signature. Then, use C's bitwise operators in your wrapper code to manually pack and unpack the values before and after the FFI call.

```c
// The native C struct with bitfields.
typedef struct {
    uint32_t a : 4; // 4 bits
    uint32_t b : 12;// 12 bits
    uint32_t c : 16;// 16 bits
} BitfieldStruct; // Total size is sizeof(uint32_t)

// The native function we want to call.
uint32_t process_bitfields(BitfieldStruct s) {
    return s.a + s.b + s.c;
}

void recipe_bitfields() {
    // 1. Describe the struct by its underlying integer storage.
    const char* signature = "({uint32}) -> uint32";
    infix_forward_t* t = NULL;
    infix_forward_create(&t, signature, (void*)process_bitfields, NULL);

    // 2. Manually pack the data into a uint32_t.
    uint32_t packed_data = 0;
    packed_data |= (15 & 0xF) << 0;  // Field a = 15
    packed_data |= (1000 & 0xFFF) << 4; // Field b = 1000
    packed_data |= (30000 & 0xFFFF) << 16; // Field c = 30000

    // 3. The FFI call sees a simple struct { uint32_t; }.
    void* args[] = { &packed_data };
    uint32_t result;

    infix_forward_get_code(t)(&result, args);
    printf("Bitfield sum: %u\n", result); // Expected: 31015

    infix_forward_destroy(t);
}
```

### Recipe: Working with Unions

**Problem**: You need to call a function that passes or returns a `union`.

**Solution**: Use the `<...>` syntax to describe the union's members.

```c
typedef union { int i; float f; } Number;
int process_number_as_int(Number n) { return n.i * 2; }

void recipe_union() {
    const char* signature = "(<int, float>) -> int";
    infix_forward_t* t = NULL;
    infix_forward_create(&t, signature, (void*)process_number_as_int, NULL);

    Number num_val;
    num_val.i = 21;
    int result = 0;
    void* args[] = {&num_val};

    infix_forward_get_code(t)(&result, args);
    printf("Result: %d\n", result);  // Expected: 42

    infix_forward_destroy(t);
}
```

### Recipe: Working with Fixed-Size Arrays

**Problem**: A function takes a fixed-size array, like `long long sum(long long arr[4]);`.

**Solution**: In C, an array argument "decays" to a pointer to its first element. The signature must reflect this. To describe the array *itself* (e.g., inside a struct), use the `[N:type]` syntax.

```c
// In C, a function parameter `arr[4]` is treated as a pointer `arr*`.
int64_t sum_array_elements(const int64_t* arr, size_t count) {
    int64_t sum = 0;
    for(size_t i = 0; i < count; ++i) sum += arr[i];
    return sum;
}

void recipe_array_decay() {
    const char* signature = "(*sint64, sint64) -> sint64";
    infix_forward_t* t = NULL;
    infix_forward_create(&t, signature, (void*)sum_array_elements, NULL);

    int64_t my_array[] = {10, 20, 30, 40};
    const int64_t* ptr_to_array = my_array;
    int64_t count = 4; // Using int64_t for sint64 signature
    void* args[] = {&ptr_to_array, &count};
    int64_t result = 0;

    infix_forward_get_code(t)(&result, args);
    printf("Sum of array is: %lld\n", (long long)result);  // Expected: 100

    infix_forward_destroy(t);
}
```

### Recipe: Advanced Named Types (Recursive & Forward-Declared)

**Problem**: You need to describe complex, real-world C data structures, such as a linked list or mutually dependent types.

**Solution**: The `infix` registry fully supports recursive definitions and forward declarations, allowing you to model these patterns cleanly.

```c
#include <infix/infix.h>
#include <stdio.h>

// C equivalent of the types we will define:
typedef struct Employee Employee;
typedef struct Manager {
    const char* name;
    Employee* reports[10]; // A manager has direct reports
} Manager;

struct Employee {
    const char* name;
    Manager* manager; // An employee has a manager
};

// A simple function to demonstrate usage
const char* get_manager_name(Employee* e) {
    return e->manager ? e->manager->name : "None";
}

void recipe_advanced_registry() {
    infix_registry_t* registry = infix_registry_create();

    // 1. Define the types. Note the forward declarations with a single ';'.
    //    This is necessary because Manager refers to Employee, and Employee
    //    refers to Manager.
    const char* definitions =
        "@Employee; @Manager;" // Forward declarations
        "@Manager = { name:*char, reports:[10:*@Employee] };"
        "@Employee = { name:*char, manager:*@Manager };"
    ;
    infix_register_types(registry, definitions);

    // 2. Create a trampoline using the named types.
    infix_forward_t* trampoline = NULL;
    infix_forward_create(&trampoline, "(*@Employee) -> *char", (void*)get_manager_name, registry);

    // 3. Set up the C data and call.
    Manager boss = { "Sanko", { NULL } };
    Employee worker = { "Robinson", &boss };
    Employee* p_worker = &worker;
    const char* manager_name = NULL;
    void* args[] = { &p_worker };

    infix_forward_get_code(trampoline)(&manager_name, args);

    printf("The manager of %s is %s.\n", worker.name, manager_name); // Expected: Sanko

    // 4. Clean up.
    infix_forward_destroy(trampoline);
    infix_registry_destroy(registry);
}
```

### Recipe: Working with Complex Numbers

**Problem**: You need to call a C function that uses `_Complex` types.

**Solution**: Use the `c[<base_type>]` constructor in the signature string.

```c
#include <complex.h>
double complex c_square(double complex z) { return z * z; }

void recipe_complex() {
    const char* signature = "(c[double]) -> c[double]";
    infix_forward_t* t = NULL;
    infix_forward_create(&t, signature, (void*)c_square, NULL);

    double complex input = 3.0 + 4.0 * I;
    double complex result;
    void* args[] = {&input};

    infix_forward_get_code(t)(&result, args);
    printf("The square of (3.0 + 4.0i) is (%.1f + %.1fi)\n", creal(result), cimag(result));

    infix_forward_destroy(t);
}
```

### Recipe: Working with SIMD Vectors

**Problem**: You need to call a high-performance C function that uses architecture-specific SIMD vector types for parallel data processing.

**Solution**: Use the generic `v[<elements>:<type>]` syntax or, where available, a convenient keyword alias (like `m512d`). The `infix` ABI logic contains the specific rules for each platform to ensure that these vectors are correctly passed in the appropriate SIMD registers (e.g., XMM/YMM/ZMM on x86-64, V/Z registers on AArch64).

This recipe is broken down by architecture, as the C types and intrinsic functions are platform-specific.

---

#### x86-64 (SSE, AVX, and AVX-512)

This example calls a function that uses AVX-512's 512-bit `__m512d` type to add two vectors of eight `double`s each. The same principle applies to 128-bit SSE (`__m128d`) and 256-bit AVX (`__m256d`) types by simply adjusting the signature.

```c
#include <infix/infix.h>
#include <stdio.h>
#include <immintrin.h> // For AVX-512 intrinsics

// Native C function using AVX-512 vectors
__m512d vector_add_512(__m512d a, __m512d b) { return _mm512_add_pd(a, b); }

void recipe_simd_avx512() {
    // The signature "m512d" is a convenient alias for "v[8:double]".
    const char* signature = "(m512d, m512d) -> m512d";
    infix_forward_t* t = NULL;
    // Note: This test must be compiled with AVX-512 support (e.g., -mavx512f)
    // and run on a CPU that supports it to avoid a crash.
    infix_forward_create(&t, signature, (void*)vector_add_512, NULL);

    // Prepare arguments using AVX-512 intrinsics.
    // _mm512_set_pd sets values from right-to-left in memory.
    __m512d a = _mm512_set_pd(8.0, 7.0, 6.0, 5.0, 4.0, 3.0, 2.0, 1.0);
    __m512d b = _mm512_set_pd(34.0, 35.0, 36.0, 37.0, 38.0, 39.0, 40.0, 41.0);
    void* args[] = {&a, &b};
    __m512d result;

    infix_forward_get_code(t)(&result, args);

    // Unpack the result for verification.
    double* d = (double*)&result;
    printf("AVX-512 vector result: [%.1f, %.1f, ..., %.1f, %.1f]\n", d[0], d[1], d[6], d[7]);
    // Expected: {1+41, 2+40, ..., 8+34} -> {42.0, 42.0, ..., 42.0, 42.0}

    infix_forward_destroy(t);
}
```

---

#### AArch64 (NEON)

This example calls a function that uses ARM NEON's `float32x4_t` type, which is a 128-bit vector of four `float`s.

```c
#include <infix/infix.h>
#include <stdio.h>
#include <arm_neon.h> // For NEON intrinsics

// Native C function that performs a horizontal add on a NEON vector.
float neon_horizontal_sum(float32x4_t vec) {
    return vaddvq_f32(vec); // Adds all four elements in the vector together.
}

void recipe_simd_neon() {
    // The signature v[4:float] directly maps to float32x4_t.
    const char* signature = "(v[4:float]) -> float";
    infix_forward_t* t = NULL;
    infix_forward_create(&t, signature, (void*)neon_horizontal_sum, NULL);

    // Prepare the NEON vector argument.
    float data[] = {10.0f, 20.0f, 5.5f, 6.5f};
    float32x4_t input_vec = vld1q_f32(data); // Load data into a vector register.
    void* args[] = {&input_vec};
    float result;

    infix_forward_get_code(t)(&result, args);

    printf("NEON horizontal sum result: %.1f\n", result); // Expected: 42.0

    infix_forward_destroy(t);
}
```

---

#### AArch64 (Scalable Vector Extension - SVE)

**Problem**: SVE vectors do not have a fixed size; their length is determined by the CPU at runtime. How can we create a trampoline for a function that uses them?

**Solution**: This requires a dynamic, multi-step approach. You must first perform a runtime check for SVE support, then query the CPU's vector length, and finally build the `infix` signature string dynamically before creating the trampoline.

```c
#include <infix/infix.h>
#include <stdio.h>
#include <stdbool.h>

#if defined(__ARM_FEATURE_SVE)
#include <arm_sve.h>
// Platform-specific headers for runtime detection
#if defined(__linux__)
#include <sys/auxv.h>
#ifndef HWCAP_SVE
#define HWCAP_SVE (1 << 22)
#endif
#elif defined(__APPLE__)
#include <sys/sysctl.h>
#endif

// Helper function to check for SVE support at runtime.
static bool is_sve_supported(void) {
#if defined(__linux__)
    return (getauxval(AT_HWCAP) & HWCAP_SVE) != 0;
#elif defined(__APPLE__)
    int sve_present = 0; size_t size = sizeof(sve_present);
    if (sysctlbyname("hw.optional.arm.FEAT_SVE", &sve_present, &size, NULL, 0) == 0)
        return sve_present == 1;
    return false;
#else // Windows, etc. would have their own checks.
    return false;
#endif
}

// Native C function using SVE for a horizontal add.
double sve_horizontal_add(svfloat64_t vec) { return svaddv_f64(svptrue_b64(), vec); }

void recipe_simd_sve() {
    if (!is_sve_supported()) {
        printf("SVE not supported on this CPU, skipping recipe.\n");
        return;
    }

    // 1. Query the vector length at runtime. svcntd() gets the count of doubles.
    size_t num_doubles = svcntd();
    printf("Detected SVE vector length: %zu doubles (%zu bits)\n", num_doubles, num_doubles * 64);

    // 2. Build the signature string dynamically.
    char signature[64];
    snprintf(signature, sizeof(signature), "(v[%zu:double]) -> double", num_doubles);
    printf("Generated signature: %s\n", signature);

    // 3. Create the trampoline with the dynamic signature.
    infix_forward_t* t = NULL;
    infix_forward_create(&t, signature, (void*)sve_horizontal_add, NULL);

    // 4. Prepare arguments and call.
    double* data = (double*)malloc(sizeof(double) * num_doubles);
    for (size_t i = 0; i < num_doubles; ++i)
        data[i] = (i == 0) ? 42.0 : 0.0; // Put 42 in the first lane.

    svbool_t pg = svptrue_b64();
    svfloat64_t input_vec = svld1_f64(pg, data);
    void* args[] = {&input_vec};
    double result;

    infix_forward_get_code(t)(&result, args);

    printf("SVE horizontal sum result: %.1f\n", result); // Expected: 42.0

    // 5. Clean up.
    free(data);
    infix_forward_destroy(t);
}

#else // If not compiled with SVE support
void recipe_simd_sve() {
    printf("SVE recipe skipped: not compiled with SVE support (e.g., -march=armv8-a+sve).\n");
}
#endif
```

### Recipe: Working with Enums

**Problem**: You need to call a C function that takes an `enum`, but you want to ensure the underlying integer type is handled correctly for ABI purposes.

**Solution**: Use the `e:<type>` syntax in the signature string. `infix` treats the enum identically to its underlying integer type for the FFI call, which is the correct behavior.

```c
// Native C enum and function
typedef enum { STATUS_OK = 0, STATUS_WARN = 1, STATUS_ERR = -1 } StatusCode;
const char* status_to_string(StatusCode code) {
    switch (code) {
        case STATUS_OK:   return "OK";
        case STATUS_WARN: return "Warning";
        case STATUS_ERR:  return "Error";
        default:          return "Unknown";
    }
}

void recipe_enums() {
    // The C `enum` is based on `int`, so we describe it as `e:int`.
    const char* signature = "(e:int) -> *char";
    infix_forward_t* t = NULL;
    infix_forward_create(&t, signature, (void*)status_to_string, NULL);

    // Pass the enum value as its underlying integer type.
    int code = STATUS_ERR;
    const char* result_str = NULL;
    void* args[] = { &code };

    infix_forward_get_code(t)(&result_str, args);

    printf("Status for code %d is '%s'\n", code, result_str); // Expected: 'Error'

    infix_forward_destroy(t);
}
```

---

## Chapter 3: The Power of Callbacks (Reverse Calls)

### Recipe: Creating a Type-Safe Callback for `qsort`

**Problem**: You need to sort an array using C's `qsort`, which requires a function pointer for the comparison logic.

**Solution**: Use `infix_reverse_create_callback`. The handler is a normal, clean C function whose signature exactly matches what `qsort` expects.

```c
#include <stdlib.h>

// 1. The handler function has a standard C signature. No context pointer is needed.
int compare_integers_handler(const void* a, const void* b) {
    return (*(const int*)a - *(const int*)b);
}

void recipe_qsort_callback() {
    // 2. Create the reverse trampoline.
    infix_reverse_t* context = NULL;
    const char* cmp_sig = "(*void, *void) -> int";
    infix_reverse_create_callback(&context, cmp_sig, (void*)compare_integers_handler, NULL);

    // 3. Get the native function pointer.
    typedef int (*compare_func_t)(const void*, const void*);
    compare_func_t my_comparator = (compare_func_t)infix_reverse_get_code(context);

    // 4. Use the generated callback with the C library function.
    int numbers[] = { 5, 1, 4, 2, 3 };
    size_t num_count = sizeof(numbers) / sizeof(numbers[0]);
    qsort(numbers, num_count, sizeof(int), my_comparator);

    printf("Sorted numbers:");
    for(size_t i = 0; i < num_count; ++i) {
        printf(" %d", numbers[i]);
    }
    printf("\n");

    infix_reverse_destroy(context);
}
```

### Recipe: Creating a Stateful Callback

**Problem**: A callback handler needs access to application state, but the C library API is stateless (it has no `void* user_data` parameter).

**Solution**: Use `infix_reverse_create_closure`. This API is specifically designed for stateful callbacks. You provide a generic handler and a `void* user_data` pointer to your state. Inside the handler, you can retrieve this pointer from the `context`.

```c
typedef struct { const char * name; int sum; } AppContext;

// 1. The handler for a closure has a generic signature.
void my_stateful_handler(infix_context_t* context, void* ret, void** args) {
    (void)ret; // This handler doesn't return a value.

    // 2. Retrieve your state from the context's user_data field.
    AppContext* ctx = (AppContext*)infix_reverse_get_user_data(context);

    // 3. Manually unbox the arguments from the void** array.
    int item_value = *(int*)args[0];

    ctx->sum += item_value;
}

// A C library function that takes a callback but no user_data.
typedef void (*item_processor_t)(int);
void process_list(const int* items, int count, item_processor_t process_func) {
    for (int i = 0; i < count; ++i) process_func(items[i]);
}

void recipe_stateful_callback() {
    // a. Prepare your state.
    AppContext ctx = {"My List", 0};

    // b. Create the closure, passing a pointer to your state as user_data.
    infix_reverse_t* rt = NULL;
    infix_reverse_create_closure(&rt, "(int) -> void", my_stateful_handler, &ctx, NULL);

    // c. Use the generated callback.
    item_processor_t processor_ptr = (item_processor_t)infix_reverse_get_code(rt);
    int list[] = {10, 20, 30};
    process_list(list, 3, processor_ptr);
    printf("Final sum for '%s': %d\n", ctx.name, ctx.sum);  // Expected: 60

    infix_reverse_destroy(rt);
}
```

---

## Chapter 4: Advanced Techniques

### Recipe: Calling Variadic Functions like `printf`

**Problem**: You need to call a function with a variable number of arguments.

**Solution**: Use the `;` token to separate fixed and variadic arguments. The signature must exactly match the types you are passing in a *specific call*.

```c
void recipe_variadic_printf() {
    const char* signature = "(*char; int, double) -> int";
    infix_forward_t* trampoline = NULL;
    infix_forward_create(&trampoline, signature, (void*)printf, NULL);

    const char* fmt = "Count: %d, Value: %.2f\n";
    int count = 42;
    double value = 123.45;
    void* args[] = { &fmt, &count, &value };
    int result;

    infix_forward_get_code(trampoline)(&result, args);
    infix_forward_destroy(trampoline);
}
```

### Recipe: Receiving and Calling a Function Pointer

**Problem**: You need to call a C function that *takes* a function pointer as an argument, and pass it a callback you generate.

**Solution**: The signature for a function pointer is `*((...) -> ...)`. Generate your callback, get its native pointer, and pass that pointer as an argument.

```c
int multiply_handler(int x) { return x * 10; }
int harness_func(int (*worker_func)(int), int base_val) { return worker_func(base_val); }

void recipe_callback_as_arg() {
    infix_reverse_t* inner_cb_ctx = NULL;
    infix_reverse_create_callback(&inner_cb_ctx, "(int)->int", (void*)multiply_handler, NULL);

    infix_forward_t* harness_trampoline = NULL;
    infix_forward_create(&harness_trampoline, "(*((int)->int), int) -> int", (void*)harness_func, NULL);

    void* inner_cb_ptr = infix_reverse_get_code(inner_cb_ctx);
    int value = 7;
    void* harness_args[] = { &inner_cb_ptr, &value };
    int result;

    infix_forward_get_code(harness_trampoline)(&result, harness_args);
    printf("Result from nested callback: %d\n", result); // Should be 70

    infix_forward_destroy(harness_trampoline);
    infix_reverse_destroy(inner_cb_ctx);
}
```

### Recipe: Calling a Function Pointer from a Struct (V-Table Emulation)

**Problem**: You have a pointer to a struct that contains function pointers, similar to a C implementation of an object's v-table. You need to read a function pointer from the struct and then call it.

**Solution**: This is a two-step FFI process. First, read the function pointer value from the struct. Second, create a new trampoline for that function pointer's signature and call it. The Type Registry is perfect for making this clean.

```c
// C equivalent of a simple "object" with a v-table.
typedef struct { int val; } Adder;
int vtable_add(Adder* self, int amount) { return self->val + amount; }
void vtable_destroy(Adder* self) { free(self); }

typedef struct {
    int (*add)(Adder* self, int amount);
    void (*destroy)(Adder* self);
} AdderVTable;

const AdderVTable VTABLE = { vtable_add, vtable_destroy };
Adder* create_adder(int base) {
    Adder* a = malloc(sizeof(Adder));
    if (a) a->val = base;
    return a;
}

void recipe_vtable_call() {
    infix_registry_t* reg = infix_registry_create();
    infix_register_types(reg,
        "@Adder = { val: int };"
        "@Adder_add_fn = (*@Adder, int) -> int;"
        "@AdderVTable = { add: *@Adder_add_fn };" // Only need to describe the one we're calling
    );

    Adder* my_adder = create_adder(100);
    const AdderVTable* vtable = &VTABLE;

    void* add_func_ptr = (void*)vtable->add;

    infix_forward_t* t_add = NULL;
    // Note: The signature here must match the member we are calling.
    infix_forward_create(&t_add, "(*@Adder, int) -> int", add_func_ptr, reg);

    int amount_to_add = 23;
    int result;
    void* add_args[] = { &my_adder, &amount_to_add };
    infix_forward_get_code(t_add)(&result, add_args);

    printf("Result from v-table call: %d\n", result); // Expected: 123

    infix_forward_destroy(t_add);
    infix_registry_destroy(reg);
    free(my_adder);
}
```

### Recipe: Handling `longdouble`

**Problem**: You need to call a function that uses `longdouble`, which has different sizes and ABI rules on different platforms (e.g., 80-bit on x86, 128-bit on AArch64, or just an alias for `double` on MSVC/macOS).

**Solution**: Use the `longdouble` keyword in your signature. `infix`'s ABI logic contains the platform-specific rules to handle it correctly, whether it's passed on the x87 FPU stack (System V x64), in a 128-bit vector register (AArch64), or as a normal `double`.

```c
#include <math.h>

// A simple function using long double.
long double native_sqrtl(long double x) {
    return sqrtl(x);
}

void recipe_long_double() {
    // On platforms where long double is distinct (like Linux), this will
    // trigger special ABI handling. On platforms where it's an alias for
    // double (like Windows), infix will treat it as a double.
    const char* signature = "(longdouble) -> longdouble";

    infix_forward_t* t = NULL;
    infix_forward_create(&t, signature, (void*)native_sqrtl, NULL);

    long double input = 144.0L;
    long double result = 0.0L;
    void* args[] = { &input };

    infix_forward_get_code(t)(&result, args);

    printf("sqrtl(144.0L) = %Lf\n", result); // Expected: 12.0

    infix_forward_destroy(t);
}
```

### Recipe: Proving Reentrancy with Nested FFI Calls

**Problem**: You need to be sure that making an FFI call from within an FFI callback is safe.

**Solution**: `infix` is designed to be fully reentrant. The library uses no global mutable state, and all error information is stored in thread-local storage. This recipe demonstrates a forward call that invokes a reverse callback, which in turn makes another forward call.

```c
#include <string.h> // For memcpy

// Innermost target function
int multiply(int a, int b) { return a * b; }

// Because this handler needs state (the forward trampoline), we MUST use a closure.
void nested_call_handler(infix_context_t* ctx, void* ret, void** args) {
    // 1. Retrieve the forward trampoline from user_data.
    infix_forward_t* fwd_trampoline = (infix_forward_t*)infix_reverse_get_user_data(ctx);

    // 2. Unbox the argument.
    int val = *(int*)args[0];
    int multiplier = 5;
    void* mult_args[] = { &val, &multiplier };

    // 3. Make the nested forward call.
    int result;
    infix_forward_get_code(fwd_trampoline)(&result, mult_args);

    // 4. Write the result to the return buffer.
    memcpy(ret, &result, sizeof(int));
}

// The outer C function that takes our generated callback
int harness(int (*func)(int), int input) {
    return func(input);
}

void recipe_reentrancy() {
    // 1. Create the innermost forward trampoline (for `multiply`)
    infix_forward_t* fwd_multiply = NULL;
    infix_forward_create(&fwd_multiply, "(int, int)->int", (void*)multiply, NULL);

    // 2. Create the reverse closure, passing the forward trampoline as user_data
    infix_reverse_t* rev_nested = NULL;
    infix_reverse_create_closure(&rev_nested, "(int)->int", nested_call_handler, fwd_multiply, NULL);

    // 3. Create the outermost forward trampoline (for `harness`)
    infix_forward_t* fwd_harness = NULL;
    const char* harness_sig = "(*((int)->int), int)->int";
    infix_forward_create(&fwd_harness, harness_sig, (void*)harness, NULL);

    // 4. Execute the call chain
    void* callback_ptr = infix_reverse_get_code(rev_nested);
    int base_val = 8;
    void* harness_args[] = { &callback_ptr, &base_val };
    int final_result;

    infix_forward_get_code(fwd_harness)(&final_result, harness_args);
    printf("Nested/reentrant call result: %d\n", final_result); // Expected: 8 * 5 = 40

    // 5. Clean up all three trampolines
    infix_forward_destroy(fwd_harness);
    infix_reverse_destroy(rev_nested);
    infix_forward_destroy(fwd_multiply);
}
```

### Recipe: Proving Thread Safety

**Problem**: You need to create a trampoline in one thread and safely use it in another.

**Solution**: `infix` trampoline handles (`infix_forward_t*` and `infix_reverse_t*`) are immutable after creation and are safe to share between threads. All error state is kept in thread-local storage, so calls from different threads will not interfere with each other.

```c
#include <infix/infix.h>
#include <stdio.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <pthread.h>
#endif

// A simple function to be the FFI target.
int add(int a, int b) { return a + b; }

// A struct to pass data to our worker thread.
typedef struct {
    infix_cif_func cif; // The callable trampoline function pointer.
    int result;
} thread_data_t;

// The function our worker thread will execute.
#if defined(_WIN32)
DWORD WINAPI worker_thread_func(LPVOID arg) {
#else
void* worker_thread_func(void* arg) {
#endif
    thread_data_t* data = (thread_data_t*)arg;
    int a = 20, b = 22;
    void* args[] = { &a, &b };
    // Call the trampoline function pointer that was created on the main thread.
    data->cif(&data->result, args);
#if defined(_WIN32)
    return 0;
#else
    return NULL;
#endif
}

void recipe_thread_safety() {
    // Main thread: Create the trampoline.
    infix_forward_t* trampoline = NULL;
    infix_forward_create(&trampoline, "(int, int)->int", (void*)add, NULL);

    thread_data_t data = { infix_forward_get_code(trampoline), 0 };

    // Main thread: Spawn a worker thread, passing it the callable pointer.
#if defined(_WIN32)
    HANDLE thread_handle = CreateThread(NULL, 0, worker_thread_func, &data, 0, NULL);
    WaitForSingleObject(thread_handle, INFINITE);
    CloseHandle(thread_handle);
#else
    pthread_t thread_id;
    pthread_create(&thread_id, NULL, worker_thread_func, &data);
    pthread_join(thread_id, NULL);
#endif

    // Main thread: Check the result computed by the worker thread.
    printf("Result from worker thread: %d\n", data.result); // Expected: 42

    // Main thread: Clean up the trampoline.
    infix_forward_destroy(trampoline);
}
```

---

## Chapter 5: Interoperability with Other Languages

### The Universal Principle: The C ABI

`infix` can call any function that exposes a standard C ABI. Nearly every compiled language provides a mechanism to export a function using this standard (`extern "C"` in C++/Rust/Zig, `//export` in Go, `bind(C)` in Fortran).

### Recipe: Interfacing with a C++ Class (Directly)

**Problem**: You need to call C++ class methods without writing a C wrapper.

**Solution**: Find the compiler-mangled names for the constructor, destructor, and methods. Use `infix` to call them directly, manually passing the `this` pointer as the first argument to methods.

```cpp
// File: MyClass.cpp (compile to libmyclass.so/.dll)
#include <iostream>
class MyClass {
    int value;
public:
    MyClass(int val) : value(val) { std::cout << "C++ Constructor called.\n"; }
    ~MyClass() { std::cout << "C++ Destructor called.\n"; }
    int add(int x) { return this->value + x; }
};
extern "C" size_t get_myclass_size() { return sizeof(MyClass); }
```

```c
// File: main.c
#include <infix/infix.h>
#include <stdio.h>
#include <stdlib.h>

// Mangled names depend on the compiler. Find them with `nm` or `dumpbin`.
#if defined(__GNUC__) || defined(__clang__) // Itanium ABI
const char* MANGLED_CONSTRUCTOR = "_ZN7MyClassC1Ei"; // MyClass::MyClass(int)
const char* MANGLED_DESTRUCTOR = "_ZN7MyClassD1Ev";  // MyClass::~MyClass()
const char* MANGLED_ADD = "_ZN7MyClass3addEi";      // MyClass::add(int)
#elif defined(_MSC_VER) // MSVC ABI
const char* MANGLED_CONSTRUCTOR = "??0MyClass@@QEAA@H@Z";
const char* MANGLED_DESTRUCTOR = "??1MyClass@@QEAA@XZ";
const char* MANGLED_ADD = "?add@MyClass@@QEAAHH@Z";
#endif

void recipe_cpp_mangled() {
    infix_library_t* lib = infix_library_open("libmyclass.so"); // or .dll
    if (!lib) return;

    void* p_ctor = infix_library_get_symbol(lib, MANGLED_CONSTRUCTOR);
    void* p_dtor = infix_library_get_symbol(lib, MANGLED_DESTRUCTOR);
    void* p_add = infix_library_get_symbol(lib, MANGLED_ADD);
    size_t (*p_size)() = infix_library_get_symbol(lib, "get_myclass_size");
    if (!p_ctor || !p_dtor || !p_add || !p_size) {
        printf("Failed to find one or more symbols.\n");
        infix_library_close(lib);
        return;
    }

    infix_forward_t *t_ctor, *t_dtor, *t_add;
    // Constructor is effectively: void __thiscall(void* this, int val)
    infix_forward_create(&t_ctor, "(*void, int)->void", p_ctor, NULL);
    // Destructor is: void __thiscall(void* this)
    infix_forward_create(&t_dtor, "(*void)->void", p_dtor, NULL);
    // Method is: int __thiscall(void* this, int x)
    infix_forward_create(&t_add, "(*void, int)->int", p_add, NULL);

    // --- Simulate `MyClass* obj = new MyClass(100);` ---
    void* obj = malloc(p_size());
    int initial_val = 100;
    infix_forward_get_code(t_ctor)(NULL, (void*[]){ &obj, &initial_val });

    // --- Simulate `int result = obj->add(23);` ---
    int add_val = 23, result;
    infix_forward_get_code(t_add)(&result, (void*[]){ &obj, &add_val });
    printf("C++ mangled method returned: %d\n", result); // Should be 123

    // --- Simulate `delete obj;` ---
    infix_forward_get_code(t_dtor)(NULL, (void*[]){ &obj });
    free(obj);

    infix_library_close(lib);
    infix_forward_destroy(t_ctor);
    infix_forward_destroy(t_dtor);
    infix_forward_destroy(t_add);
}
```

### Recipe: Interfacing with C++ Templates

**Problem**: How do you call a C++ function template from C?

**Solution**: You can't call the template itself, but you can call a *specific instantiation* of it. The compiler generates a normal function for each concrete type used with the template, and this function has a predictable mangled name that you can look up and call.

```cpp
// File: Box.cpp (compile to libbox.so/.dll)
#include <iostream>
template <typename T>
class Box {
    T value;
public:
    Box(T val) : value(val) {}
    T get_value() { return this->value; }
};

// We need to explicitly instantiate the templates we want to use
// so the compiler generates code for them.
template class Box<int>;
template class Box<double>;
```

```c
// File: main.c
#include <infix/infix.h>
#include <stdio.h>
#include <stdlib.h>

// Mangled name for `Box<double>::get_value()` on GCC/Clang
const char* MANGLED_GET_DBL = "_ZNK3BoxIdE9get_valueEv";

void recipe_cpp_template() {
    infix_library_t* lib = infix_library_open("libbox.so");
    if (!lib) return;

    // Manually create a Box<double> for this example.
    double val = 3.14;
    void* my_box = malloc(sizeof(double));
    memcpy(my_box, &val, sizeof(double));

    void* p_get_value = infix_library_get_symbol(lib, MANGLED_GET_DBL);
    if (!p_get_value) {
        printf("Failed to find mangled template function.\n");
        free(my_box);
        infix_library_close(lib);
        return;
    }

    infix_forward_t* t_get = NULL;
    // Signature: double get_value(Box<double>* this)
    infix_forward_create(&t_get, "(*void) -> double", p_get_value, NULL);

    double result;
    infix_forward_get_code(t_get)(&result, (void*[]){ &my_box });

    printf("Value from C++ template object: %f\n", result); // Should be 3.14

    free(my_box);
    infix_forward_destroy(t_get);
    infix_library_close(lib);
}
```

### The Pattern for Other Compiled Languages

The `extern "C"` pattern is universal. The C code to call any of the functions below would be identical: load the library, find the symbol, create a trampoline for `(int, int) -> int`, and call it.

#### Rust

To export a C-compatible function from Rust, use `#[no_mangle]` to prevent name mangling and `extern "C"` to specify the calling convention.

```rust
// librust_math.rs
#[no_mangle]
pub extern "C" fn rust_add(a: i32, b: i32) -> i32 {
    a + b
}
```

*Compile with: `rustc --crate-type cdylib librust_math.rs`*

#### Zig

Zig's `export` keyword makes a function available with the C ABI by default.

```zig
// libzig_math.zig
export fn zig_add(a: c_int, b: c_int) c_int {
    return a + b;
}
```

*Compile with: `zig build-lib -dynamic libzig_math.zig`*

#### Go

Go can export functions to C using a special `//export` comment directive.

```go
// libgo_math.go
package main
import "C"

//export go_add
func go_add(a C.int, b C.int) C.int { return a + b }
func main() {}
```

*Compile with: `go build -buildmode=c-shared -o libgo_math.so libgo_math.go`*

#### Swift

The `@_cdecl` attribute exposes a Swift function to C with a specified name.

```swift
// libswift_math.swift
@_cdecl("swift_add")
public func swift_add(a: CInt, b: CInt) -> CInt {
    return a + b
}
```

*Compile with: `swiftc -emit-library libswift_math.swift -o libswift_math.so`*

#### Dlang

The `extern(C)` attribute specifies the C calling convention for a D function.

```d
// libd_math.d
extern (C) int d_add(int a, int b) { return a + b; }
```

*Compile with: `dmd -shared -fPIC -of=libd_math.so libd_math.d`*

#### Fortran

The `bind(C)` attribute from the `iso_c_binding` module provides C interoperability.

```fortran
! libfortran_math.f90
function fortran_add(a, b) result(c) bind(C, name='fortran_add')
    use iso_c_binding
    integer(c_int), value :: a, b
    integer(c_int) :: c
    c = a + b
end function fortran_add
```

*Compile with: `gfortran -shared -fPIC -o libfortran_math.so libfortran_math.f90`*

#### Assembly

Pure machine code has no name mangling. You just need to follow the target ABI's calling convention.

```nasm
; libasm_math.asm (for System V x64 ABI)
section .text
global asm_add
asm_add:
    mov eax, edi ; Move first argument (RDI) into EAX
    add eax, esi ; Add second argument (RSI) to EAX
    ret          ; Return value is in EAX
```

*Compile with: `nasm -f elf64 libasm_math.asm && gcc -shared -o libasm_math.so libasm_math.o`*

## Chapter 6: Dynamic Libraries & System Calls

### Recipe: Calling Native System Libraries without Linking

**Problem**: You need to call a function from a system library (e.g., `user32.dll`) without linking against its import library at compile time.

**Solution**: Use `infix`'s cross-platform library loading API to get a handle to the library and the function pointer, then create a trampoline.

```c
#include <infix/infix.h>
#include <stdio.h>

#if defined(_WIN32)
#include <windows.h> // For UINT
void recipe_system_call() {
    infix_library_t* user32 = infix_library_open("user32.dll");
    if (!user32) {
        printf("Failed to open user32.dll\n");
        return;
    }

    void* pMessageBoxA = infix_library_get_symbol(user32, "MessageBoxA");
    if (!pMessageBoxA) {
        printf("Failed to find MessageBoxA\n");
        infix_library_close(user32);
        return;
    }

    // int MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
    // Note: HWND is a pointer, LPCSTR is *char, UINT is uint32.
    const char* sig = "(*void, *char, *char, uint32) -> int";
    infix_forward_t* t = NULL;
    infix_forward_create(&t, sig, pMessageBoxA, NULL);

    void* hwnd = NULL;
    const char* text = "Hello from a dynamically loaded function!";
    const char* caption = "infix FFI";
    uint32_t type = 0; // MB_OK
    void* args[] = { &hwnd, &text, &caption, &type };
    int result;

    infix_forward_get_code(t)(&result, args);

    infix_forward_destroy(t);
    infix_library_close(user32);
}
#else
// Dummy implementation for non-Windows platforms to allow compilation.
void recipe_system_call() {
    printf("This recipe is for Windows only.\n");
}
#endif
```

### Recipe: Reading and Writing Global Variables

**Problem**: You need to access a global variable exported from a shared library, not just a function.

**Solution**: Use `infix_read_global()` and `infix_write_global()`. The powerful signature language is used to describe the variable's type, ensuring `infix` reads or writes the correct number of bytes.

#### Example 1: Simple Integer Variable

First, create a simple shared library (`libglobals.c`) that exports a counter:

```c
// libglobals.c - Compile to a shared library
#if defined(_WIN32)
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

EXPORT int global_counter = 42;
```

Now, the C code to interact with it:

```c
#include <infix/infix.h>
#include <stdio.h>

void recipe_global_int() {
    infix_library_t* lib = infix_library_open("./libglobals.so"); // or "libglobals.dll"
    if (!lib) return;

    int counter_val = 0;

    // 1. Read the initial value. The signature is simply the type of the variable.
    infix_read_global(lib, "global_counter", "int", &counter_val);
    printf("Initial value of global_counter: %d\n", counter_val); // Expected: 42

    // 2. Write a new value to the global variable.
    int new_val = 100;
    infix_write_global(lib, "global_counter", "int", &new_val);

    // 3. Read the value again to confirm it was changed.
    counter_val = 0; // Reset our local variable
    infix_read_global(lib, "global_counter", "int", &counter_val);
    printf("New value of global_counter: %d\n", counter_val); // Expected: 100

    infix_library_close(lib);
}
```

#### Example 2: Aggregate (Struct) Variable

Let's expand `libglobals.c` to export a configuration struct:

```c
// Add to libglobals.c
typedef struct {
    const char* name;
    int version;
} Config;

EXPORT Config g_config = { "default", 1 };
```

Now, the C code to read and write this struct:

```c
#include <infix/infix.h>
#include <stdio.h>
#include <string.h>

typedef struct { const char* name; int version; } Config;

void recipe_global_struct() {
    infix_library_t* lib = infix_library_open("./libglobals.so");
    if (!lib) return;

    // It's good practice to use the registry for structs.
    infix_registry_t* reg = infix_registry_create();
    infix_register_types(reg, "@Config = {*char, int};");

    Config local_config;

    // 1. Read the global struct into our local variable.
    infix_read_global(lib, "g_config", "@Config", &local_config);
    printf("Initial config: name='%s', version=%d\n", local_config.name, local_config.version);

    // 2. Modify and write the struct back to the library.
    Config new_config = { "updated", 2 };
    infix_write_global(lib, "g_config", "@Config", &new_config);

    // 3. Read it back to verify the change.
    memset(&local_config, 0, sizeof(Config));
    infix_read_global(lib, "g_config", "@Config", &local_config);
    printf("Updated config: name='%s', version=%d\n", local_config.name, local_config.version);

    infix_registry_destroy(reg);
    infix_library_close(lib);
}
```

### Recipe: Handling Library Dependencies

**Problem:** You want to load a library (`libA`) that itself depends on another shared library (`libB`).

**Solution:** You don't have to do anything special. On all modern operating systems, the dynamic linker will automatically find, load, and link `libB` when you load `libA`.

```c
// libB.c -> provides a helper function
int helper_from_lib_b() { return 100; }

// libA.c -> depends on libB
int helper_from_lib_b();
int entry_point_a() { return 200 + helper_from_lib_b(); }

// How to compile:
// gcc -shared -fPIC -o libB.so libB.c
// gcc -shared -fPIC -o libA.so libA.c -L. -lB // Link libA against libB

void recipe_library_dependencies() {
    // We only need to open libA. The OS will handle loading libB.
    infix_library_t* lib = infix_library_open("./libA.so");
    if (!lib) return;

    void* p_entry = infix_library_get_symbol(lib, "entry_point_a");
    infix_forward_t* t = NULL;
    infix_forward_create(&t, "()->int", p_entry, NULL);

    int result;
    infix_forward_get_code(t)(&result, NULL);

    printf("Result from chained libraries: %d\n", result); // Should be 300

    infix_forward_destroy(t);
    infix_library_close(lib);
}
```

---

## Chapter 7: Introspection for Data Marshalling

### Recipe: Dynamic Struct Marshalling with the Signature Parser

**Problem**: You have data from a dynamic source (like a script) and need to pack it into a C `struct` layout at runtime.

**Solution**: Use `infix_type_from_signature` to parse a signature into a detailed `infix_type` graph. This graph contains all the `size`, `alignment`, and member `offset` information needed to correctly write data into a C-compatible memory buffer.

```c
#include <infix/infix.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef struct { int32_t user_id; double score; const char* name; } UserProfile;

void marshal_ordered_data(void* dest, const char* sig, void** src) {
    infix_type* type = NULL;
    infix_arena_t* arena = NULL;
    if (infix_type_from_signature(&type, &arena, sig, NULL) != INFIX_SUCCESS) return;

    for (size_t i = 0; i < infix_type_get_member_count(type); ++i) {
        const infix_struct_member* member = infix_type_get_member(type, i);
        memcpy((char*)dest + member->offset, src[i], infix_type_get_size(member->type));
    }
    infix_arena_destroy(arena);
}

void recipe_dynamic_packing() {
    int32_t id = 123;
    double score = 98.6;
    const char* name = "Sanko";
    void* my_data[] = { &id, &score, &name };

    const char* profile_sig = "{id:int32, score:double, name:*char}";
    UserProfile profile_buffer = {0};

    marshal_ordered_data(&profile_buffer, profile_sig, my_data);
    printf("Resulting C struct: id=%d, score=%.1f, name=%s\n",
           profile_buffer.user_id, profile_buffer.score, profile_buffer.name);
}
```

### Recipe: Building a Signature String at Runtime

**Problem**: The structure of the data you need to work with isn't known until runtime (e.g., it's defined in a configuration file or a user script).

**Solution**: Since `infix` signatures are just strings, you can build them dynamically using `snprintf`. You can then parse this dynamic signature to get layout information, which is perfect for data marshalling or dynamic RPC systems.

```c
// Imagine this data comes from a config file
const char* user_defined_fields[] = { "int", "int", "double" };
int num_fields = 3;

void recipe_dynamic_signature() {
    char signature_buffer = "{";
    char* current = signature_buffer + 1;
    size_t remaining = sizeof(signature_buffer) - 1;

    // 1. Build the signature string dynamically.
    for (int i = 0; i < num_fields; ++i) {
        int written = snprintf(current, remaining, "%s%s", user_defined_fields[i], (i == num_fields - 1) ? "" : ",");
        if (written < 0 || (size_t)written >= remaining) {
            printf("Error: Signature buffer too small.\n");
            return;
        }
        current += written;
        remaining -= written;
    }
    strcat(signature_buffer, "}"); // Final string is "{int,int,double}"

    printf("Dynamically generated signature: %s\n", signature_buffer);

    // 2. Use the dynamic signature to get layout information.
    infix_type* dynamic_type = NULL;
    infix_arena_t* arena = NULL;
    infix_type_from_signature(&dynamic_type, &arena, signature_buffer, NULL);

    if (dynamic_type) {
        printf("Dynamic struct size: %zu bytes\n", infix_type_get_size(dynamic_type));
    }

    infix_arena_destroy(arena);
}
```

### Recipe: Introspecting a Trampoline for a Wrapper

**Problem**: You are building a language binding and need to validate the number and types of arguments provided by the user before making an FFI call.

**Solution**: Use the trampoline introspection API to query the signature information stored in the handle.

```c
void dynamic_wrapper(infix_forward_t* trampoline, void* target_func, void** args, size_t num_provided_args) {
    if (num_provided_args != infix_forward_get_num_args(trampoline)) {
        fprintf(stderr, "Error: Incorrect number of arguments. Expected %zu, got %zu.\n",
                infix_forward_get_num_args(trampoline), num_provided_args);
        return;
    }
    // A real binding would also check the types using infix_forward_get_arg_type().
    ((infix_unbound_cif_func)infix_forward_get_unbound_code(trampoline))(target_func, NULL, args);
}
```

---

## Chapter 8: Performance & Memory Management

### Best Practice: Caching Trampolines

**Rule**: **NEVER** generate a new trampoline for the same function signature inside a hot loop. The performance of `infix` comes from amortizing the one-time generation cost over many fast calls.

```c
// FAST: Create once, call many times
infix_forward_t* t = NULL;
infix_forward_create(&t, "(int, int) -> int", my_func, NULL);
infix_cif_func cif = infix_forward_get_code(t);
int result;
void* args[] = { /* ... */ };
for (int i = 0; i < 1000000; ++i) {
    cif(&result, args); // VERY FAST
}
infix_forward_destroy(t);
```

### Recipe: Using a Custom Arena for a Group of Types

**Goal:** Create a set of related `infix_type` objects for the Manual API and free them all at once.

```c
void recipe_custom_arena() {
    infix_arena_t* arena = infix_arena_create(8192);
    infix_type* int_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);

    infix_type* int_array_type = NULL;
    infix_type_create_array(arena, &int_array_type, int_type, 100);

    // ... use these types with `infix_forward_create_manual` ...

    // A single call to destroy the arena cleans up everything allocated from it.
    infix_arena_destroy(arena);
}
```

### Recipe: The Full Manual API Lifecycle (Types to Trampoline)

**Problem**: You want to create a trampoline without using the signature parser, for maximum performance or because your type information is already structured in C.

**Solution**: Use an arena to build your `infix_type` objects and then pass them directly to the `_manual` variant of the creation functions.

```c
#include <infix/infix.h>
#include <stdio.h>
#include <stddef.h> // For offsetof

// The C types and function we want to call
typedef struct { double x, y; } Point;
Point move_point(Point p, double dx) { p.x += dx; return p; }

void recipe_full_manual_api() {
    // 1. Create an arena to hold all our type definitions.
    infix_arena_t* arena = infix_arena_create(4096);

    // 2. Manually define the 'Point' struct type.
    infix_struct_member point_members[] = {
        infix_type_create_member("x", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(Point, x)),
        infix_type_create_member("y", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(Point, y))
    };
    infix_type* point_type = NULL;
    infix_type_create_struct(arena, &point_type, point_members, 2);

    // 3. Define the argument types for the function `Point move_point(Point, double)`.
    infix_type* arg_types[] = {
        point_type,
        infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE)
    };

    // 4. Create the trampoline using the manually created types.
    infix_forward_t* trampoline = NULL;
    infix_forward_create_manual(&trampoline, point_type, arg_types, 2, 2, (void*)move_point);

    // 5. Call the function.
    Point start = { 10.0, 20.0 };
    double delta_x = 5.5;
    void* args[] = { &start, &delta_x };
    Point end;

    infix_forward_get_code(trampoline)(&end, args);
    printf("Manual API result: Moved point has x = %f\n", end.x); // Should be 15.5

    // 6. Clean up.
    infix_forward_destroy(trampoline);
    infix_arena_destroy(arena); // Frees the 'point_type' as well.
}
```

### Recipe: Using Custom Memory Allocators

**Problem**: Your application uses a custom memory manager for tracking, pooling, or integration with a garbage collector. You need `infix` to use your allocators instead of the standard `malloc`, `calloc`, etc.

**Solution**: `infix` provides override macros (`infix_malloc`, `infix_free`, etc.). Define these macros *before* you include `infix.h` to redirect all of its internal memory operations.

```c
#include <stdio.h>
#include <stdlib.h>

// 1. Define your custom memory management functions.
static size_t g_total_allocated = 0;
void* tracking_malloc(size_t size) {
    g_total_allocated += size;
    printf(">> Custom Malloc: Allocating %zu bytes (Total: %zu)\n", size, g_total_allocated);
    return malloc(size);
}

void tracking_free(void* ptr) {
    printf(">> Custom Free\n");
    free(ptr);
}

// 2. Define the infix override macros BEFORE including infix.h
#define infix_malloc(size) tracking_malloc(size)
#define infix_free(ptr)    tracking_free(ptr)
// You can also override infix_calloc and infix_realloc if needed.

#include <infix/infix.h>

void recipe_custom_allocators() {
    printf("Creating trampoline with custom allocators\n");
    infix_forward_t* trampoline = NULL;
    // All internal allocations for the trampoline will now use tracking_malloc.
    infix_forward_create(&trampoline, "()->void", (void*)recipe_custom_allocators, NULL);

    printf("Destroying trampoline\n");
    // The free operations will now use tracking_free.
    infix_forward_destroy(trampoline);
    printf("Done\n");
}
```

### Recipe: Building a Dynamic Call Frame with an Arena

**Problem**: You are writing a language binding (e.g., for Python, Perl, Lua) and need to build the `void* args[]` array at runtime. The arguments are coming from the host language, so you need to unbox them into temporary C values, create an array of pointers to these temporary values, and then clean everything up after the call. Doing this with `malloc` for every call in a tight loop is inefficient.

**Solution**: Use an `infix` arena to allocate memory for both the unboxed C values *and* the `void**` array that points to them. This makes the entire call frame a single, contiguous block of memory that can be allocated and freed with extreme efficiency.

```c
#include <infix/infix.h>
#include <stdio.h>
#include <stdarg.h> // For va_list
#include <string.h> // For memcpy

// A sample C function we want to call dynamically.
void process_user_data(int id, double score, const char* name) {
    printf("C Function Received: ID=%d, Score=%.2f, Name='%s'\n", id, score, name);
}

// This function simulates the core logic of a language binding's generic "call" function.
// It takes a va_list to represent dynamic arguments coming from a script.
void dynamic_ffi_call(infix_forward_t* trampoline, void* target_func, int arg_count, ...) {
    // 1. Create a temporary arena for this call's entire data frame.
    infix_arena_t* call_arena = infix_arena_create(4096);
    if (!call_arena) {
        fprintf(stderr, "Error: Could not create call arena.\n");
        return;
    }

    // 2. Allocate the void** array itself from the arena.
    void** args = infix_arena_alloc(call_arena, sizeof(void*) * arg_count, _Alignof(void*));

    va_list va;
    va_start(va, arg_count);

    // 3. For each argument, allocate space for its C value in the arena,
    //    copy the value, and store the pointer in the `args` array.
    for (int i = 0; i < arg_count; ++i) {
        // In a real binding, you would inspect the trampoline's arg types here.
        // For this example, we'll assume the order int, double, const char*.
        if (i == 0) { // int
            int* val_ptr = infix_arena_alloc(call_arena, sizeof(int), _Alignof(int));
            *val_ptr = va_arg(va, int);
            args[i] = val_ptr;
        }
        else if (i == 1) { // double
            double* val_ptr = infix_arena_alloc(call_arena, sizeof(double), _Alignof(double));
            *val_ptr = va_arg(va, double);
            args[i] = val_ptr;
        }
        else if (i == 2) { // const char*
            const char** val_ptr = infix_arena_alloc(call_arena, sizeof(const char*), _Alignof(const char*));
            *val_ptr = va_arg(va, const char*);
            args[i] = val_ptr;
        }
    }
    va_end(va);

    // 4. Make the FFI call using the arena-managed data.
    infix_unbound_cif_func cif = infix_forward_get_unbound_code(trampoline);
    cif(target_func, NULL, args);

    // 5. A single free cleans up the void** array AND all the argument values.
    infix_arena_destroy(call_arena);
}

void recipe_arena_call_frame() {
    // Setup the trampoline once and cache it (as a real binding would).
    const char* signature = "(int, double, *char) -> void";
    infix_forward_t* trampoline = NULL;
    infix_forward_create_unbound(&trampoline, signature, NULL);

    printf("Making dynamic FFI call\n");
    dynamic_ffi_call(trampoline, (void*)process_user_data, 3,
                     123, 99.8, "test user");

    infix_forward_destroy(trampoline);
}
```

#### How It Works & Why It's Better

1.  **Unified Allocation**: Instead of multiple calls to `malloc` (one for the `args` array, one for the `int`, one for the `double`, etc.), all memory is sourced from a single arena.

2.  **Performance**: The allocations within the arena are extremely fast "bump" allocations, which is significantly cheaper than heap allocation, especially for many small objects.

3.  **Simplified Cleanup**: All temporary data for the call—the `void**` array and the unboxed C values—lives in the arena. A single call to `infix_arena_destroy` cleans everything up instantly, eliminating the risk of memory leaks from forgetting to `free` one of the many small allocations.

#### Advanced Optimization: Arena Resetting for Hot Loops

For a binding that needs to make many FFI calls in a tight loop, you can achieve even higher performance by creating the arena *once* outside the loop and "resetting" it on each iteration. Since `infix_arena_t` is not an opaque type, you can do this manually:

```c
// Inside a hypothetical binding's loop...
infix_arena_t* loop_arena = infix_arena_create(65536);
for (int i = 0; i < 1000; ++i) {
    // Before building the args, save the current allocation point.
    size_t arena_state = loop_arena->current_offset;

    // ... build the void** args and argument values from the arena ...
    // ... make the FFI call ...

    // Instead of destroying the arena, just reset the offset.
    // This is virtually free and avoids all allocation/deallocation overhead inside the loop.
    loop_arena->current_offset = arena_state;
}
infix_arena_destroy(loop_arena);
```

---

## Chapter 9: Common Pitfalls & Troubleshooting

### Recipe: Advanced Error Reporting for the Parser

**Problem**: A user provides an invalid signature string, and you want to give them a helpful error message indicating exactly where the syntax error occurred.

**Solution**: After a parsing function fails, call `infix_get_last_error()` and use the `position`, `code`, and `message` fields to generate a detailed diagnostic.

```c
#include <infix/infix.h>
#include <stdio.h>

void report_parse_error(const char* signature) {
    infix_type* type = NULL;
    infix_arena_t* arena = NULL;
    infix_status status = infix_type_from_signature(&type, &arena, signature, NULL);

    if (status != INFIX_SUCCESS) {
        infix_error_details_t err = infix_get_last_error();
        fprintf(stderr, "Failed to parse signature:\n");
        fprintf(stderr, "  %s\n", signature);
        // Print a caret '^' pointing to the error location.
        fprintf(stderr, "  %*s^\n", (int)err.position, "");
        fprintf(stderr, "Error: %s (code: %d, position: %zu)\n",
                err.message, err.code, err.position);
    }
    else
        printf("Successfully parsed signature: %s\n", signature);

    infix_arena_destroy(arena);
}

void recipe_error_reporting() {
    // This signature has an invalid character '^' instead of a comma.
    report_parse_error("{int, double, ^*char}");
}

/*
Expected output:
Failed to parse signature:
  {int, double, ^*char}
               ^
Error Code: 200 at position 15
*/
```

### Mistake: Passing a Value Instead of a Pointer in `args[]`

*   **Symptom**: Crash or garbage data.

*   **Explanation**: The `args` array for a forward call must be an array of **pointers to** your argument values, not the values themselves.

### Mistake: `infix` Signature Mismatch

*   **Symptom**: Silent data corruption, garbage values, or a crash.

*   **Explanation**: The signature string must *exactly* match the C type's size and alignment. A `long` is 32 bits on 64-bit Windows but 64 bits on 64-bit Linux.

*   **Solution**: Use fixed-width types (`int32`, `uint64`) whenever possible.

### Pitfall: Function Pointer Syntax

*   **Symptom**: Parser error.

*   **Explanation**: A function type is `(...) -> ...`, and a pointer is `*...`. Therefore, a pointer to a function type is `*((...) -> ...)`.

*   **Solution**: `int (*callback)(void)` becomes `*(() -> int)`.

---

## Chapter 10: A Comparative Look: `infix` vs. `libffi` and `dyncall`

This chapter provides a practical, code-level comparison of `infix` with two other popular FFI libraries: `libffi` (the industry standard) and `dyncall`. All three are powerful tools, but they are built with different philosophies and trade-offs. We will compare them across three common FFI tasks.

### Scenario 1: Calling a Simple Function

**Goal**: Call a simple function `double add_doubles(double a, double b);`. This demonstrates the core calling mechanism and API ergonomics.

#### The `dyncall` Approach

`dyncall` uses a "call virtual machine" (VM) where arguments are pushed one-by-one. The setup cost is incurred on **every call**, making it very flexible but less performant for repeated calls to the same function.

```c
#include <dyncall.h>
// ...
DCCallVM* vm = dcNewCallVM(4096);
double result;

// Per-call setup and execution
dcReset(vm);
dcArgDouble(vm, 1.5);
dcArgDouble(vm, 2.5);
result = dcCallDouble(vm, (DCpointer)&add_doubles); // result is 4.0

dcFree(vm);
```

#### The `libffi` Approach

`libffi` requires a one-time "Call Interface" (`ffi_cif`) preparation. Subsequent calls are fast, but the initial type definition is manual and programmatic.

```c
#include <ffi.h>
// ...
ffi_cif cif;
ffi_type* args_types[] = { &ffi_type_double, &ffi_type_double };
ffi_type* ret_type = &ffi_type_double;

// One-time setup
ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 2, ret_type, args_types);

double a = 1.5, b = 2.5;
void* args_values[] = { &a, &b };
double result;

// Subsequent calls are fast
ffi_call(&cif, FFI_FN(add_doubles), &result, args_values);
```

#### The `infix` Approach

`infix` combines the performance model of `libffi` (one-time setup) with a much higher-level, human-readable API. The key difference is the use of a simple signature string.

```c
#include <infix/infix.h>
// ...
infix_forward_t* t = NULL;
// One-time setup from a simple string
infix_forward_create(&t, "(double, double) -> double", (void*)add_doubles, NULL);
infix_cif_func cif = infix_forward_get_code(t);

double a = 1.5, b = 2.5;
void* args[] = { &a, &b };
double result;

// Subsequent calls are very fast
cif(&result, args);
```

### Scenario 2: Calling a Function with a Struct

**Goal**: Call `Point move_point(Point p);` where `Point` is `{double, double}`. This highlights the critical differences in type systems.

#### The `dyncall` Approach

`dyncall` requires manual construction of an aggregate object (`DCaggr`) to describe the struct layout. This must be done at runtime before the call.

```c
#include <dyncall.h>
#include <dyncall_aggregate.h>
// ...
typedef struct { double x, y; } Point;
DCCallVM* vm = dcNewCallVM(4096);

// 1. Manually describe the struct layout for dyncall
DCaggr* ag = dcNewAggr(2); // 2 members
dcAggrField(ag, DC_TYPE_DOUBLE, DC_ALIGNMENT_DOUBLE, 1); // member x
dcAggrField(ag, DC_TYPE_DOUBLE, DC_ALIGNMENT_DOUBLE, 1); // member y
dcCloseAggr(ag);

// 2. Prepare the struct data and call
Point p_in = {10.0, 20.0};
Point p_out;
dcReset(vm);
dcArgAggr(vm, ag, &p_in);
dcCallAggr(vm, (DCpointer)&move_point, ag, &p_out);

dcFreeAggr(ag);
dcFree(vm);
```

#### The `libffi` Approach

`libffi` also requires programmatic struct definition, which is done by creating an `ffi_type` struct and an array for its elements.

```c
#include <ffi.h>
// ...
typedef struct { double x, y; } Point;

// 1. Manually define the struct layout for libffi
ffi_type point_elements[] = { &ffi_type_double, &ffi_type_double, NULL };
ffi_type point_type;
point_type.size = 0; point_type.alignment = 0;
point_type.type = FFI_TYPE_STRUCT;
point_type.elements = point_elements;

// 2. Prepare the CIF using the new struct type
ffi_cif cif;
ffi_type* args_types[] = { &point_type };
ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 1, &point_type, args_types);

// 3. Prepare args and call
Point p_in = {10.0, 20.0};
Point p_out;
void* args_values[] = { &p_in };
ffi_call(&cif, FFI_FN(move_point), &p_out, args_values);
```

#### The `infix` Approach

`infix` handles the entire struct definition within the signature string, making the C code for the FFI call trivial and declarative.

```c
#include <infix/infix.h>
// ...
typedef struct { double x, y; } Point;

// 1. Describe the struct and function in one line.
const char* signature = "({double, double}) -> {double, double}";
infix_forward_t* t = NULL;
infix_forward_create(&t, signature, (void*)move_point, NULL);

// 2. Prepare args and call.
Point p_in = {10.0, 20.0};
Point p_out;
void* args[] = { &p_in };
infix_forward_get_code(t)(&p_out, args);

infix_forward_destroy(t);
```

### Scenario 3: Creating a Callback

**Goal**: Create a native C function pointer from a custom handler to be used by `qsort`.

#### The `dyncall` Approach

`dyncallback` requires creating a `DCCallback` object and initializing it with a C function that uses a special `dcbArg*` API to retrieve arguments one by one.

```c
#include <dyncall_callback.h>

// 1. The handler uses the dyncallback API to get arguments.
void qsort_handler_dc(DCCallback* cb, DCArgs* args, DCValue* result, void* userdata) {
    const int* a = (const int*)dcbArgPointer(args);
    const int* b = (const int*)dcbArgPointer(args);
    result->i = (*a - *b);
}

// 2. Create the callback object.
DCCallback* cb = dcbNewCallback("pp)i", &qsort_handler_dc, NULL);
qsort(numbers, 5, sizeof(int), (void*)cb);
dcbFree(cb);
```

#### The `libffi` Approach

`libffi` can create a "closure" which is a block of executable memory that acts as the C function pointer. The handler receives arguments via `ffi_call`-style arrays.

```c
#include <ffi.h>

// 1. The handler receives arguments in libffi's generic format.
void qsort_handler_ffi(ffi_cif* cif, void* ret, void** args, void* userdata) {
    const int* a = *(const int**)args;
    const int* b = *(const int**)args;
    *(ffi_sarg*)ret = (*a - *b);
}

// 2. Prepare the CIF for the callback's signature.
ffi_cif cif;
ffi_type* args_types[] = { &ffi_type_pointer, &ffi_type_pointer };
ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 2, &ffi_type_sint, args_types);

// 3. Allocate and create the closure.
void* func_ptr = NULL;
ffi_closure* closure = ffi_closure_alloc(sizeof(ffi_closure), &func_ptr);
ffi_prep_closure_loc(closure, &cif, qsort_handler_ffi, NULL, func_ptr);
qsort(numbers, 5, sizeof(int), (void*)func_ptr);
ffi_closure_free(closure);
```

#### The `infix` Approach

`infix` generates a reverse trampoline. The handler is a normal C function that receives its arguments directly, prefixed by the `infix_context_t*`.

```c
#include <infix/infix.h>

// 1. The handler is a standard C function with the context as the first argument.
int qsort_handler_infix(infix_context_t* ctx, const int* a, const int* b) {
    (void)ctx;
    return (*a - *b);
}

// 2. Create the reverse trampoline from a signature.
infix_reverse_t* context = NULL;
infix_reverse_create_callback(&context, "(*void, *void)->int", (void*)qsort_handler_infix, NULL, NULL);

// 3. Get the native function pointer and use it.
typedef int (*compare_func_t)(const void*, const void*);
compare_func_t my_comparator = (compare_func_t)infix_reverse_get_code(context);
qsort(numbers, 5, sizeof(int), my_comparator);

infix_reverse_destroy(context);
```

### Analysis and Takeaways

| Aspect            | `dyncall`                             | `libffi`                                             | `infix`                                                                  |
| :---------------- | :------------------------------------ | :--------------------------------------------------- | :----------------------------------------------------------------------- |
| **Readability**   | Low (single-character signatures)     | Medium (C code is clear, but type setup is verbose)  | **High** (Human-readable, self-contained signature strings)              |
| **Performance Model** | Setup cost on **every call**          | **One-time setup** (`ffi_prep_cif`)                  | **One-time setup** (JIT compilation)                                     |
| **Type System**   | Programmatic, with struct support     | Manual, programmatic `ffi_type` creation             | **Integrated**. Types are part of the signature string, with registry support. |
| **Ease of Use**   | Simple for primitives, complex for structs | Complex, powerful, requires deep knowledge of the API | **Simple and Declarative**, designed for a high-level experience.        |
| **Callback Handler**| Special API (`dcbArg*`)              | Generic `void**` arguments                           | **Native C arguments** (callback) or **Generic `void**` (closure).       |

---

## Chapter 11: Building Language Bindings

### The Four Pillars of a Language Binding
A robust language binding built on `infix` must solve four main challenges:

1.  **Type Mapping & Signature Generation:** The binding's primary job is to translate the host language's type representation (e.g., Python's `ctypes.c_int`) into an `infix` signature string.
2.  **Trampoline Caching:** The binding **must** implement a global, persistent cache for trampolines, using the signature string as the key, to amortize the one-time JIT compilation cost.
3.  **Memory & Lifetime Management:** The binding must act as a bridge between the host language's Garbage Collector (GC) and C's manual memory management, holding references to objects to prevent premature collection.
4.  **The Callback Bridge:** A C handler must be implemented to transfer control from a native C call back into the host language's runtime, handling argument unmarshalling and potential GIL (Global Interpreter Lock) acquisition. This should use the `infix_reverse_create_closure` API.

### Recipe: Porting a Python Binding from `dyncall` to `infix`

This recipe demonstrates how one might port a Python binding from a library like `dyncall` to `infix`.

**The `dyncall` approach** involves a "call virtual machine" (`DCCallVM*`) that arguments are pushed to one-by-one at call time. This is flexible but incurs overhead on every call.

**The `infix` approach** shifts the expensive work (parsing and code generation) to a one-time setup phase, making subsequent calls much faster. The core logic of the binding becomes centered around a trampoline cache.

```c
// Conceptual port to infix for a Python module
#include <Python.h>
#include <infix/infix.h>
#include <alloca.h> // For alloca

// A global Python dictionary to cache trampolines: { signature_str: PyCapsule(trampoline) }
static PyObject* g_trampoline_cache = NULL;

static PyObject* infix_python_call(PyObject* self, PyObject* py_args) {
    PyObject* target_func_capsule = NULL;
    const char* signature = NULL;
    PyObject* py_func_args = NULL;
    if (!PyArg_ParseTuple(py_args, "OsO!", &target_func_capsule, &signature, &PyTuple_Type, &py_func_args)) return NULL;

    void* target_func = PyCapsule_GetPointer(target_func_capsule, NULL);
    if(!target_func) return NULL;

    if (g_trampoline_cache == NULL) g_trampoline_cache = PyDict_New();

    // 1. Trampoline Caching
    PyObject* signature_py = PyUnicode_FromString(signature);
    PyObject* capsule = PyDict_GetItem(g_trampoline_cache, signature_py);
    infix_forward_t* trampoline = NULL;

    if (capsule)
        trampoline = (infix_forward_t*)PyCapsule_GetPointer(capsule, "infix_trampoline");
    else {
        // Not in cache: create, then store in cache via a PyCapsule.
        if (infix_forward_create_unbound(&trampoline, signature, NULL) != INFIX_SUCCESS) {
            PyErr_SetString(PyExc_RuntimeError, "Failed to create infix trampoline.");
            Py_DECREF(signature_py);
            return NULL;
        }
        capsule = PyCapsule_New(trampoline, "infix_trampoline", (PyCapsule_Destructor)infix_forward_destroy);
        PyDict_SetItem(g_trampoline_cache, signature_py, capsule);
        Py_DECREF(capsule);
    }
    Py_DECREF(signature_py);

    // 2. Argument Marshalling (simplified)
    size_t num_args = PyTuple_GET_SIZE(py_func_args);
    void** c_args = (void**)alloca(sizeof(void*) * num_args);
    // In a real binding, this storage would need to be managed more robustly.
    // Using an infix_arena_t here is the recommended production approach.
    void* storage = alloca(1024);
    char* storage_ptr = (char*)storage;

    for (size_t i = 0; i < num_args; ++i) {
        PyObject* py_arg = PyTuple_GET_ITEM(py_func_args, i);
        if (PyLong_Check(py_arg)) {
            long* val = (long*)storage_ptr; *val = PyLong_AsLong(py_arg);
            c_args[i] = val; storage_ptr += sizeof(long);
        }
        else if (PyFloat_Check(py_arg)) {
            double* val = (double*)storage_ptr; *val = PyFloat_AsDouble(py_arg);
            c_args[i] = val; storage_ptr += sizeof(double);
        } // ... etc.
    }

    // 3. The FFI Call
    infix_unbound_cif_func cif = infix_forward_get_unbound_code(trampoline);
    // A real binding would inspect the signature to handle the return value.
    cif(target_func, NULL, c_args);

    Py_RETURN_NONE;
}
```
