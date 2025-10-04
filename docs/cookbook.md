# The `infix` FFI Cookbook

This guide provides practical, real-world examples to help you solve common FFI problems and leverage the full power of the `infix` library. Where the `README.md` covers concepts, this cookbook provides the code.

> **Note:** For a complete reference on the string format used in these examples (e.g., `"int"`, `"{double, double}"`, `"*char"`), please see the **[Signature Language Reference](signatures.md)**.

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
    *   [Recipe: Working with Packed Structs](#recipe-working-with-packed-structs)
    *   [Recipe: Working with Unions](#recipe-working-with-unions)
    *   [Recipe: Working with Pointers to Arrays](#recipe-working-with-pointers-to-arrays)
    *   [Recipe: Working with Complex Numbers](#recipe-working-with-complex-numbers)
    *   [Recipe: Working with SIMD Vectors](#recipe-working-with-simd-vectors)
    *   [Recipe: Introspecting a Trampoline for a Wrapper](#recipe-introspecting-a-trampoline-for-a-wrapper)
*   **Chapter 3: The Power of Callbacks (Reverse Calls)**
    *   [Recipe: Creating a Stateless Callback for `qsort`](#recipe-creating-a-stateless-callback-for-qsort)
    *   [Recipe: Creating a Stateful Callback (The Modern Way)](#recipe-creating-a-stateful-callback-the-modern-way)
*   **Chapter 4: Advanced Techniques**
    *   [Recipe: Calling Variadic Functions like `printf`](#recipe-calling-variadic-functions-like-printf)
    *   [Recipe: Creating a Variadic Callback](#recipe-creating-a-variadic-callback)
    *   [Recipe: Proving Reentrancy with Nested FFI Calls](#recipe-proving-reentrancy-with-nested-ffi-calls)
    *   [Recipe: Receiving and Calling a Function Pointer](#recipe-receiving-and-calling-a-function-pointer)
*   **Chapter 5: Interoperability with Other Languages**
    *   [The Universal Principle: The C ABI](#the-universal-principle-the-c-abi)
    *   [Recipe: Interfacing with a C++ Class](#recipe-interfacing-with-a-c-class)
    *   [The Pattern for Other Compiled Languages](#the-pattern-for-other-compiled-languages)
*   **Chapter 6: Calling System Libraries**
    *   [Recipe: Calling Native System Libraries](#recipe-calling-native-system-libraries)
*   **Chapter 7: Memory Management & Performance**
    *   [Best Practice: Caching Trampolines](#best-practice-caching-trampolines)
*   **Chapter 8: Common Pitfalls & Troubleshooting**
    *   [Mistake: Passing a Value Instead of a Pointer in `args[]`](#mistake-passing-a-value-instead-of-a-pointer-in-args)
    *   [Mistake: `infix` Signature Mismatch](#mistake-infix-signature-mismatch)
    *   [Pitfall: Function Pointer Syntax](#pitfall-function-pointer-syntax)
*   **Chapter 9: Building Language Bindings**
    *   [The Four Pillars of a Language Binding](#the-four-pillars-of-a-language-binding)

---

## Chapter 1: The Basics (Forward Calls)

### Recipe: Calling a Simple C Function

**Problem**: You want to call a standard C function, like `int add(int, int);`.

**Solution**: Describe the function's signature using the v1.0 format (`"(int32, int32) -> int32"`), prepare pointers to your arguments, and invoke the function through the generated trampoline.

```c
#include <infix/infix.h>
#include <stdio.h>

// The C function we want to call dynamically.
int add_ints(int a, int b) {
    return a + b;
}

int main() {
    // 1. Describe the signature: int(int, int).
    const char * signature = "(int32, int32) -> int32";

    // 2. Generate the trampoline. This is the one-time setup cost.
    infix_forward_t * trampoline = NULL;
    infix_forward_create(&trampoline, signature);

    // 3. Prepare arguments. The args array must hold *pointers* to the values.
    int a = 40, b = 2;
    void * args[] = {&a, &b};
    int result = 0;

    // 4. Get the callable function pointer and invoke it.
    infix_cif_func cif_func = (infix_cif_func)infix_forward_get_code(trampoline);
    cif_func((void *)add_ints, &result, args);

    printf("Result of add_ints(40, 2) is: %d\n", result);  // Expected: 42

    // 5. Clean up.
    infix_forward_destroy(trampoline);
    return 0;
}
```

### Recipe: Passing and Receiving Pointers

**Problem**: You need to call a C function that takes pointers as arguments, like `void swap(int* a, int* b);`.

**Solution**: Use the `*` prefix modifier in the signature string (`"(*int32, *int32) -> void"`). The values you pass in the `args` array are the addresses of your pointer variables.

```c
#include <infix/infix.h>
#include <stdio.h>

// A C function that takes pointers and modifies the values they point to.
void swap_ints(int * a, int * b) {
    int temp = *a;
    *a = *b;
    *b = temp;
}

int main() {
    // 1. Describe the signature: void(int*, int*)
    const char * signature = "(*int32, *int32) -> void";
    infix_forward_t * trampoline = NULL;
    infix_forward_create(&trampoline, signature);

    // 2. Prepare arguments.
    int x = 10, y = 20;
    int * ptr_x = &x;  // These pointers are the actual arguments.
    int * ptr_y = &y;

    // The `args` array for infix must hold the addresses *of our pointer variables*.
    void * args[] = {&ptr_x, &ptr_y};

    printf("Before swap: x = %d, y = %d\n", x, y);

    // 3. Call the function via the trampoline.
    ((infix_cif_func)infix_forward_get_code(trampoline))((void *)swap_ints, NULL, args);

    printf("After swap: x = %d, y = %d\n", x, y);  // Expected: x = 20, y = 10

    // 4. Clean up.
    infix_forward_destroy(trampoline);
    return 0;
}
```

### Recipe: Working with Opaque Pointers (Incomplete Types)

**Problem**: You need to interact with a C library that uses opaque pointers (or "handles") where the internal structure is hidden.

**Solution**: Use the `*void` signature. This is the canonical representation for a generic handle or opaque pointer.

```c
#include <infix/infix.h>
#include <stdio.h>
#include <stdlib.h>

// --- Mock C Library with Opaque Pointers ---
struct my_handle { int value; };
typedef struct my_handle my_handle_t;

my_handle_t * create_handle(int initial_value) {
    my_handle_t * h = (my_handle_t *)malloc(sizeof(my_handle_t));
    if (h) { h->value = initial_value; }
    return h;
}
void destroy_handle(my_handle_t * handle) { free(handle); }
int get_handle_value(my_handle_t * handle) { return handle ? handle->value : -1; }
// --- End Mock Library ---

int main() {
    // 1. Create trampolines for the C API using signatures.
    //    `*void` is the signature for any opaque pointer or handle.
    infix_forward_t *t_create, *t_destroy, *t_get;
    infix_forward_create(&t_create, "(int) -> *void");
    infix_forward_create(&t_destroy, "(*void) -> void");
    infix_forward_create(&t_get, "(*void) -> int");

    // 2. Use the API through the trampolines.
    my_handle_t * handle = NULL;
    int initial_val = 123;
    void * create_args[] = {&initial_val};
    ((infix_cif_func)infix_forward_get_code(t_create))((void *)create_handle, &handle, create_args);

    if (handle) {
        int value = 0;
        void * handle_arg[] = {&handle};
        ((infix_cif_func)infix_forward_get_code(t_get))((void *)get_handle_value, &value, handle_arg);
        printf("Value from handle: %d\n", value);  // Expected: 123

        ((infix_cif_func)infix_forward_get_code(t_destroy))((void *)destroy_handle, NULL, handle_arg);
    }

    // 3. Clean up.
    infix_forward_destroy(t_create);
    infix_forward_destroy(t_destroy);
    infix_forward_destroy(t_get);
    return 0;
}
```

### Recipe: Working with Fixed-Size Arrays

**Problem**: You need to call a function that operates on a fixed-size array, like `long long sum_array(long long arr[4]);`.

**Solution**: In C, an array argument "decays" to a pointer to its first element. The signature must reflect this (`"(*int64) -> int64"`). `infix` will handle the call correctly.

```c
#include <infix/infix.h>
#include <stdint.h>
#include <stdio.h>

// In C, a function parameter `arr[4]` is treated as a pointer `arr*`.
int64_t sum_array_elements(const int64_t * arr) {
    int64_t sum = 0;
    for (int i = 0; i < 4; ++i) sum += arr[i];
    return sum;
}

int main() {
    // 1. Signature describes the decayed pointer type: int64_t(const int64_t*)
    const char * signature = "(*int64) -> int64";
    infix_forward_t * trampoline = NULL;
    infix_forward_create(&trampoline, signature);

    // 2. Prepare the array and the pointer to it.
    int64_t my_array[] = {10, 20, 30, 40};
    const int64_t * ptr_to_array = my_array;
    void * args[] = {&ptr_to_array};
    int64_t result = 0;

    // 3. Invoke the call.
    ((infix_cif_func)infix_forward_get_code(trampoline))((void *)sum_array_elements, &result, args);

    printf("Sum of array is: %lld\n", (long long)result);  // Expected: 100

    infix_forward_destroy(trampoline);
    return 0;
}
```

---

## Chapter 2: Handling Complex Data Structures

### Recipe: Dynamic Struct Marshalling with the Signature Parser

**Problem**: You have data from a dynamic source (e.g., a script) and need to pack it into a C `struct` layout at runtime.

**Solution**: Use `infix_type_from_signature` to parse a signature string into a detailed `infix_type` graph. This graph contains all the `size`, `alignment`, and member `offset` information needed to correctly write data into a C-compatible memory buffer.

```c
#include <infix/infix.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// The C struct we want to pack data into.
typedef struct {
    int32_t user_id;
    double score;
    const char * name;
} UserProfile;

// This function dynamically packs data into a buffer according to the signature.
void marshal_ordered_data(void * dest_buffer, const char * signature, void ** source_values) {
    infix_type * struct_type = NULL;
    infix_arena_t * arena = NULL;

    // 1. Parse the signature to get the type layout information.
    if (infix_type_from_signature(&struct_type, &arena, signature) != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to parse signature.\n");
        return;
    }

    // 2. Iterate through the members described by the parsed type.
    for (size_t i = 0; i < infix_type_get_member_count(struct_type); ++i) {
        const infix_struct_member * member = infix_type_get_member(struct_type, i);

        // 3. Copy the source data to the correct offset in the destination buffer.
        memcpy((char *)dest_buffer + member->offset, source_values[i], infix_type_get_size(member->type));
    }
    infix_arena_destroy(arena);
}

int main() {
    void * my_data[] = {
        &(int32_t){123},
        &(double){98.6},
        &(const char *){"Sanko"}
    };
    const char * profile_sig = "{id:int32, score:double, name:*char}";

    UserProfile profile_buffer = {0};
    marshal_ordered_data(&profile_buffer, profile_sig, my_data);

    printf("Resulting C struct:\n  user_id: %d\n  score:   %f\n  name:    %s\n",
           profile_buffer.user_id, profile_buffer.score, profile_buffer.name);

    return 0;
}
```

### Recipe: Small Structs Passed by Value

**Problem**: You need to call a function that takes a small `struct` that the ABI passes in registers.

**Solution**: Use the anonymous struct syntax `({...})`. `infix` will automatically determine the correct ABI passing convention.

```c
#include <infix/infix.h>
#include <stdio.h>

typedef struct { double x; double y; } Point;

// A C function that takes a small struct by value.
double process_point(Point p) {
    return p.x + p.y;
}

int main() {
    // 1. Describe the signature: double(Point).
    const char * signature = "({double, double}) -> double";
    infix_forward_t * trampoline = NULL;
    infix_forward_create(&trampoline, signature);

    // 2. Prepare the struct argument.
    Point p = {1.5, 2.5};
    void * args[] = {&p};
    double result = 0;

    // 3. Call the function.
    ((infix_cif_func)infix_forward_get_code(trampoline))((void *)process_point, &result, args);

    printf("Result is: %f\n", result);  // Expected: 4.0

    infix_forward_destroy(trampoline);
    return 0;
}
```

### Recipe: Large Structs Passed by Reference

**Problem**: A function takes a struct that is too large to fit in registers.

**Solution**: The process is identical to the small struct example. `infix`'s ABI logic will detect that the struct is large and automatically pass it by reference (by passing a pointer).

```c
#include <infix/infix.h>
#include <stdio.h>

typedef struct { int a, b, c, d, e, f; } LargeStruct;

// A C function that takes a large struct. The ABI will pass it by reference.
int sum_large_struct_fields(LargeStruct s) {
    return s.a + s.f;
}

int main() {
    // 1. Signature: int(LargeStruct).
    const char * signature = "({int,int,int,int,int,int}) -> int";
    infix_forward_t * trampoline = NULL;
    infix_forward_create(&trampoline, signature);

    // 2. The process is identical. `infix` handles the pass-by-reference detail.
    LargeStruct data = {10, 20, 30, 40, 50, 60};
    void * args[] = {&data};
    int result = 0;

    ((infix_cif_func)infix_forward_get_code(trampoline))((void *)sum_large_struct_fields, &result, args);

    printf("Result is: %d\n", result);  // Expected: 70

    infix_forward_destroy(trampoline);
    return 0;
}
```

### Recipe: Receiving a Struct from a Function

**Problem**: You need to call a function that *returns* a struct by value.

**Solution**: Simply use the struct signature as the return type (e.g., `"() -> {double, double}"`).

```c
#include <infix/infix.h>
#include <stdio.h>

typedef struct { double x; double y; } Point;

// A C function that returns a struct by value.
Point create_point() {
    return (Point){100.0, 200.0};
}

int main() {
    // 1. Signature: Point(void).
    const char * signature = "() -> {double, double}";
    infix_forward_t * trampoline = NULL;
    infix_forward_create(&trampoline, signature);

    // 2. Prepare a buffer to receive the returned struct.
    Point result_point;

    // 3. Call the function.
    ((infix_cif_func)infix_forward_get_code(trampoline))((void *)create_point, &result_point, NULL);

    printf("Returned point: (%f, %f)\n", result_point.x, result_point.y);

    infix_forward_destroy(trampoline);
    return 0;
}
```

### Recipe: Working with Packed Structs

**Problem**: You need to call a C function that takes a packed struct.

**Solution**: Use the `!{...}` syntax. The `!` prefix tells `infix` to use a packed layout with 1-byte alignment. For other alignments, use `!N:{...}`.

```c
#include <infix/infix.h>
#include <stdint.h>
#include <stdio.h>

#pragma pack(push, 1)
typedef struct { char a; uint64_t b; } PackedStruct;
#pragma pack(pop)

int process_packed(PackedStruct p) {
    return (p.a == 'X' && p.b == 0x1122334455667788ULL) ? 42 : -1;
}

int main() {
    // 1. Describe the packed struct using the `!{...}` syntax.
    const char * signature = "(!{char, uint64}) -> int";
    infix_forward_t * trampoline = NULL;
    infix_forward_create(&trampoline, signature);

    // 2. Prepare arguments and call.
    PackedStruct data = {'X', 0x1122334455667788ULL};
    int result = 0;
    void * args[] = {&data};
    ((infix_cif_func)infix_forward_get_code(trampoline))((void *)process_packed, &result, args);

    printf("Packed struct result: %d\n", result);  // Expected: 42
    infix_forward_destroy(trampoline);
    return 0;
}
```

### Recipe: Working with Unions

**Problem**: You need to call a function that passes or returns a `union`.

**Solution**: Use the `<...>` syntax to describe the union.

```c
#include <infix/infix.h>
#include <stdio.h>

typedef union { int i; float f; } Number;

int process_number_as_int(Number n) {
    return n.i * 2;
}

int main() {
    // 1. Signature for int(Number).
    const char * signature = "(<int, float>) -> int";
    infix_forward_t * trampoline = NULL;
    infix_forward_create(&trampoline, signature);

    // 2. Prepare the union argument.
    Number num_val;
    num_val.i = 21;
    int result = 0;
    void * args[] = {&num_val};

    // 3. Call the function.
    ((infix_cif_func)infix_forward_get_code(trampoline))((void *)process_number_as_int, &result, args);
    printf("Result: %d\n", result);  // Expected: 42

    infix_forward_destroy(trampoline);
    return 0;
}
```

### Recipe: Working with Pointers to Arrays

**Problem**: You need to call a function that takes a pointer to a fixed-size array, like `void process_matrix(int (*matrix)[4]);`.

**Solution**: Use the pointer prefix `*` on an array type (`*[4:int32]`).

```c
#include <infix/infix.h>
#include <stdio.h>

// This function expects a pointer to an array of 4 integers.
void process_matrix_row(int (*row_ptr)) {
    printf("Processing row: ");
    for (int i = 0; i < 4; ++i) {
        printf("%d ", (*row_ptr)[i]);
    }
    printf("\n");
}

int main() {
    // 1. Signature for void(int(*)).
    const char * signature = "(*[4:int32]) -> void";
    infix_forward_t * trampoline = NULL;
    infix_forward_create(&trampoline, signature);

    // 2. Prepare arguments.
    int matrix = {{1, 2, 3, 4}, {5, 6, 7, 8}};
    int(*ptr_to_first_row) = &matrix;

    void * args[] = {&ptr_to_first_row};

    // 3. Call the function.
    ((infix_cif_func)infix_forward_get_code(trampoline))((void *)process_matrix_row, NULL, args);

    infix_forward_destroy(trampoline);
    return 0;
}
```

### Recipe: Working with Complex Numbers

**Problem**: You need to call a C function that uses `_Complex` types.

**Solution**: Use the `c[...]` constructor in the signature string.

```c
#include <complex.h>
#include <infix/infix.h>
#include <stdio.h>

double complex c_square(double complex z) {
    return z * z;
}

int main() {
    // 1. Signature for: double complex(double complex)
    const char * signature = "(c[double]) -> c[double]";
    infix_forward_t * trampoline = NULL;
    infix_forward_create(&trampoline, signature);

    // 2. Prepare arguments.
    double complex input = 3.0 + 4.0 * I;
    double complex result;
    void * args[] = {&input};

    // 3. Call the function.
    ((infix_cif_func)infix_forward_get_code(trampoline))((void *)c_square, &result, args);

    printf("The square of (3.0 + 4.0i) is (%.1f + %.1fi)\n", creal(result), cimag(result));
    // Expected: -7.0 + 24.0i

    infix_forward_destroy(trampoline);
    return 0;
}
```

### Recipe: Working with SIMD Vectors

**Problem**: You need to call a high-performance C function that uses SIMD vector types (like SSE's `__m128d`).

**Solution**: Use the `v[<N>:<type>]` syntax. The ABI logic will ensure the vector is correctly passed in a SIMD register (e.g., XMM on x86-64).

```c
#include <emmintrin.h> // For SSE2 intrinsics like __m128d
#include <infix/infix.h>
#include <stdio.h>

// A C function that takes two SSE vectors and returns their dot product.
double dot_product(__m128d v1, __m128d v2) {
    __m128d xy = _mm_mul_pd(v1, v2);
    __m128d temp = _mm_shuffle_pd(xy, xy, 1);
    __m128d sum = _mm_add_pd(xy, temp);
    return _mm_cvtsd_f64(sum);
}

int main() {
    // 1. Signature for: double( __m128d, __m128d )
    //    An __m128d is a vector of 2 doubles, so the signature is v[2:double].
    const char * signature = "(v[2:double], v[2:double]) -> double";
    infix_forward_t * trampoline = NULL;
    infix_forward_create(&trampoline, signature);

    // 2. Prepare the vector arguments.
    __m128d vec1 = _mm_set_pd(2.0, 3.0); // Creates vector [3.0, 2.0]
    __m128d vec2 = _mm_set_pd(4.0, 5.0); // Creates vector [5.0, 4.0]
    void * args[] = {&vec1, &vec2};
    double result = 0;

    // 3. Call the function.
    ((infix_cif_func)infix_forward_get_code(trampoline))((void *)dot_product, &result, args);

    // Dot product is (3.0 * 5.0) + (2.0 * 4.0) = 15.0 + 8.0 = 23.0
    printf("Dot product is: %f\n", result); // Expected: 23.0

    infix_forward_destroy(trampoline);
    return 0;
}
```

### Recipe: Introspecting a Trampoline for a Wrapper

**Problem**: You are building a language binding and need to verify the number and types of arguments provided by the user at call time.

**Solution**: Use the forward trampoline introspection API to query the signature information.

```c
#include <infix/infix.h>
#include <stdio.h>

// A dynamic wrapper that uses the introspection API to validate arguments.
void dynamic_wrapper(infix_forward_t* trampoline, void* target_func, void** args, size_t num_provided_args) {
    size_t num_expected_args = infix_forward_get_num_args(trampoline);
    if (num_provided_args != num_expected_args) {
        fprintf(stderr, "Error: Expected %zu arguments, but got %zu.\n", num_expected_args, num_provided_args);
        return;
    }
    // A real binding would also check the types of the provided arguments.

    ((infix_cif_func)infix_forward_get_code(trampoline))(target_func, NULL, args);
}

void my_c_func(int a, double b) { printf("my_c_func called with: %d, %f\n", a, b); }

int main() {
    infix_forward_t* trampoline = NULL;
    infix_forward_create(&trampoline, "(int32, double) -> void");

    int arg1 = 42;
    double arg2 = 3.14;
    void* good_args[] = {&arg1, &arg2};

    dynamic_wrapper(trampoline, (void*)my_c_func, good_args, 2);

    infix_forward_destroy(trampoline);
    return 0;
}
```

---

## Chapter 3: The Power of Callbacks (Reverse Calls)

### Recipe: Creating a Stateless Callback for `qsort`

**Problem**: You need to sort an array using C's `qsort`, which requires a function pointer for the comparison logic.

**Solution**: Use a reverse trampoline. The handler's signature must accept `infix_context_t*` as its first argument and a pointer for the return value.

```c
#include <infix/infix.h>
#include <stdio.h>
#include <stdlib.h>

// qsort expects: int(const void*, const void*)
// Our handler is: void(infix_context_t*, int*, const void*, const void*)
void compare_ints_handler(infix_context_t * context, int* retval, const void * a, const void * b) {
    (void)context;
    int int_a = *(const int *)a;
    int int_b = *(const int *)b;
    *retval = (int_a > int_b) - (int_a < int_b);
}

int main() {
    // 1. Describe the signature `qsort` expects.
    const char * qsort_compare_sig = "(*void, *void) -> int32";
    infix_reverse_t * rt = NULL;
    infix_reverse_create(&rt, qsort_compare_sig, (void *)compare_ints_handler, NULL);

    // 2. Get the native, callable function pointer.
    int (*comparison_func_ptr)(const void *, const void *) =
        (int (*)(const void *, const void *))infix_reverse_get_code(rt);

    // 3. Call `qsort` with our generated function pointer.
    int numbers[] = {5, 2, 8, 1, 9};
    qsort(numbers, 5, sizeof(int), comparison_func_ptr);

    printf("Sorted numbers: 1 2 5 8 9\n");

    infix_reverse_destroy(rt);
    return 0;
}
```

### Recipe: Creating a Stateful Callback (The Modern Way)

**Problem**: A callback handler needs access to application state, but the C library API is stateless.

**Solution**: `infix` automatically passes a pointer to the `infix_context_t` as the **first argument** to every C callback handler. Retrieve your application state from the context's `user_data` field.

```c
#include <infix/infix.h>
#include <stdio.h>

// A mock C library with a stateless callback API.
typedef void (*item_processor_t)(int item_value);
void process_list(int * items, int count, item_processor_t process_func) {
    for (int i = 0; i < count; ++i)  process_func(items[i]);
}

typedef struct { const char * name; int sum; } AppContext;

// Our handler receives the context as its first argument.
void my_stateful_handler(infix_context_t * context, int item_value) {
    // Retrieve our application's state from the user_data pointer!
    AppContext * ctx = (AppContext *)infix_reverse_get_user_data(context);
    ctx->sum += item_value;
}

int main() {
    AppContext ctx = {"My List", 0};

    // 1. Create a reverse trampoline, passing a pointer to our AppContext as user_data.
    infix_reverse_t * rt = NULL;
    infix_reverse_create(&rt, "(int) -> void", (void *)my_stateful_handler, &ctx);

    item_processor_t processor_ptr = (item_processor_t)infix_reverse_get_code(rt);

    // 2. Call the C library.
    int list[] = {10, 20, 30};
    process_list(list, 3, processor_ptr);

    printf("Final sum: %d\n", ctx.sum);  // Expected: 60

    infix_reverse_destroy(rt);
    return 0;
}
```

---

## Chapter 4: Advanced Techniques

### Recipe: Calling Variadic Functions like `printf`

**Problem**: You need to call a function with a variable number of arguments.

**Solution**: Use the `;` token to separate fixed and variadic arguments in the signature.

```c
#include <infix/infix.h>
#include <stdio.h>

int main() {
    // 1. Describe the *specific instance* of the call:
    //    int printf(const char* format, int, const char*);
    const char * signature = "(*char; int, *char) -> int";
    infix_forward_t * trampoline = NULL;
    infix_forward_create(&trampoline, signature);

    // 2. Prepare arguments for this specific call.
    const char * fmt = "Number: %d, String: %s\n";
    int val = 123;
    const char * str = "test";
    void * args[] = {&fmt, &val, &str};
    int result = 0;

    // 3. Call printf through the trampoline.
    ((infix_cif_func)infix_forward_get_code(trampoline))((void *)printf, &result, args);

    printf("printf returned %d\n", result);

    infix_forward_destroy(trampoline);
    return 0;
}
```

### Recipe: Creating a Variadic Callback

**Problem**: You need to create a native function pointer for a handler that is itself variadic.

**Solution**: Your C handler will use `<stdarg.h>`. The `infix` signature includes the `;` token after the fixed arguments.

```c
#include <infix/infix.h>
#include <stdarg.h>
#include <stdio.h>

// Our C handler is itself variadic.
void my_logger(infix_context_t * context, const char * level, const char * format, ...) {
    (void)context;
    printf("[%s] ", level);
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

typedef void (*log_func_t)(const char *, const char *, ...);
void run_logger(log_func_t logger) {
    logger("INFO", "User logged in with ID %d\n", 42);
}

int main() {
    // The semicolon indicates where the variadic arguments begin.
    const char * signature = "(*char, *char; int) -> void";
    infix_reverse_t * rt = NULL;
    infix_reverse_create(&rt, signature, (void *)my_logger, NULL);

    run_logger((log_func_t)infix_reverse_get_code(rt));

    infix_reverse_destroy(rt);
    return 0;
}
```

### Recipe: Proving Reentrancy with Nested FFI Calls

**Problem**: You need to call a C function that takes a callback, and inside that callback handler, you need to call *another* C function using `infix`.

**Solution**: `infix` is fully reentrant. Create all necessary trampolines upfront and use them as needed.

```c
#include <infix/infix.h>
#include <stdio.h>

// --- Mock C Library ---
static void (*g_handler)(int) = NULL;
void log_event(const char * msg) { printf("C Log: %s\n", msg); }
void register_handler(void (*h)(int)) { g_handler = h; }
void run_loop() { if (g_handler) g_handler(42); }
// --- End Mock ---

static infix_forward_t * g_log_trampoline = NULL;

// Our callback handler.
void my_handler(infix_context_t * context, int event_code) {
    (void)context;
    const char * log_msg = "Event processed inside handler.";
    void * log_args[] = {&log_msg};
    // Nested call: a forward FFI call made from within a reverse FFI call.
    ((infix_cif_func)infix_forward_get_code(g_log_trampoline))((void *)log_event, NULL, log_args);
}

int main() {
    infix_forward_create(&g_log_trampoline, "(*char) -> void");

    infix_reverse_t * rt = NULL;
    infix_reverse_create(&rt, "(int) -> void", (void *)my_handler, NULL);
    void * handler_ptr = infix_reverse_get_code(rt);

    infix_forward_t *t_register, *t_run;
    // Signature for register_handler: void(void(*)(int))
    infix_forward_create(&t_register, "(*((int) -> void)) -> void");
    infix_forward_create(&t_run, "() -> void");

    ((infix_cif_func)infix_forward_get_code(t_register))((void *)register_handler, NULL, &handler_ptr);
    ((infix_cif_func)infix_forward_get_code(t_run))((void *)run_loop, NULL, NULL);

    infix_forward_destroy(g_log_trampoline);
    infix_reverse_destroy(rt);
    infix_forward_destroy(t_register);
    infix_forward_destroy(t_run);
    return 0;
}
```

### Recipe: Receiving and Calling a Function Pointer

**Problem**: You need to call a factory function that returns a pointer to another function, which you then need to call.

**Solution**: Use two reverse trampolines. The "provider" callback returns a pointer to the "worker" callback. The signature for a function pointer is `*((...)->...)`.

```c
#include <infix/infix.h>
#include <stdio.h>

void final_multiply_handler(infix_context_t * context, int* retval, int val) {
    (void)context;
    *retval = val * 10;
}

void callback_provider_handler(infix_context_t * context, void** retval) {
    *retval = infix_reverse_get_user_data(context);
}

typedef int (*worker_func_t)(int);
typedef worker_func_t (*provider_func_t)(void);

int call_harness(provider_func_t provider, int input_val) {
    worker_func_t worker = provider();
    return worker(input_val);
}

int main() {
    infix_reverse_t * worker_rt = NULL;
    infix_reverse_create(&worker_rt, "(int) -> int", (void *)final_multiply_handler, NULL);

    infix_reverse_t * provider_rt = NULL;
    void * worker_ptr = infix_reverse_get_code(worker_rt);
    infix_reverse_create(&provider_rt, "() -> *void", (void *)callback_provider_handler, worker_ptr);

    const char * harness_sig = "(*(() -> *void), int) -> int";
    infix_forward_t * harness_ft = NULL;
    infix_forward_create(&harness_ft, harness_sig);

    provider_func_t provider_ptr = (provider_func_t)infix_reverse_get_code(provider_rt);
    int input = 7;
    int result = 0;
    void * harness_args[] = {&provider_ptr, &input};

    ((infix_cif_func)infix_forward_get_code(harness_ft))((void *)call_harness, &result, harness_args);

    printf("Final result: %d\n", result);  // Expected: 70

    infix_forward_destroy(harness_ft);
    infix_reverse_destroy(provider_rt);
    infix_reverse_destroy(worker_rt);
    return 0;
}
```

---

## Chapter 5: Interoperability with Other Languages

### The Universal Principle: The C ABI

It is possible to call a function written in Rust, Fortran, or C++ from C because of a shared standard: the **C Application Binary Interface (ABI)**. Nearly every compiled language provides a mechanism to expose a function using the C ABI. Once you have a C-compatible function pointer, `infix` can call it.

### Recipe: Interfacing with a C++ Class

**Problem**: You need to create, use, and destroy a C++ object from a pure C environment.

**Solution**: Create a simple C-style API in your C++ code using `extern "C"`. `infix` can then call this clean, predictable API, using `*void` as the opaque handle for the object pointer.

```c
// File: lib/counter.hpp
#pragma once
#ifdef __cplusplus
class Counter {
public:
    Counter();
    void add(int value);
    int get() const;
private:
    int count;
};
extern "C" {
#endif
typedef struct Counter Counter;
Counter * Counter_create();
void Counter_destroy(Counter * c);
void Counter_add(Counter * c, int value);
int Counter_get(Counter * c);
#ifdef __cplusplus
}
#endif

// File: 18_cpp_example.c
#include "lib/counter.hpp"
#include <infix/infix.h>
#include <stdio.h>

int main() {
    infix_forward_t *t_create, *t_destroy, *t_add, *t_get;
    infix_forward_create(&t_create, "() -> *void");
    infix_forward_create(&t_destroy, "(*void) -> void");
    infix_forward_create(&t_add, "(*void, int) -> void");
    infix_forward_create(&t_get, "(*void) -> int");

    Counter * counter_obj = NULL;
    ((infix_cif_func)infix_forward_get_code(t_create))((void *)Counter_create, &counter_obj, NULL);

    if (counter_obj) {
        int val_to_add = 50;
        void * add_args[] = {&counter_obj, &val_to_add};
        ((infix_cif_func)infix_forward_get_code(t_add))((void *)Counter_add, NULL, add_args);

        int final_val = 0;
        void * get_args[] = {&counter_obj};
        ((infix_cif_func)infix_forward_get_code(t_get))((void *)Counter_get, &final_val, get_args);
        printf("[C] Final value from C++ object: %d\n", final_val);

        ((infix_cif_func)infix_forward_get_code(t_destroy))((void *)Counter_destroy, NULL, get_args);
    }

    infix_forward_destroy(t_create); /* ... destroy others ... */
    return 0;
}
```

### The Pattern for Other Compiled Languages

The following examples demonstrate how to export a simple `int add(int, int)` function from a shared library. The `infix` C code is nearly identical in every case, highlighting the power of the C ABI.

#### Rust
```rust
// librust_math.rs
#[no_mangle]
pub extern "C" fn rust_add(a: i32, b: i32) -> i32 {
    a + b
}
```
*Compile with: `rustc --crate-type cdylib librust_math.rs`*

#### Fortran
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

#### Zig
```zig
// libzig_math.zig
export fn zig_add(a: c_int, b: c_int) c_int {
    return a + b;
}
```
*Compile with: `zig build-lib -dynamic libzig_math.zig`*

#### Go
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
```swift
// libswift_math.swift
@_cdecl("swift_add")
public func swift_add(a: CInt, b: CInt) -> CInt {
    return a + b
}
```
*Compile with: `swiftc -emit-library libswift_math.swift -o libswift_math.so`*

#### D (dlang)
```d
// libd_math.d
extern (C) int d_add(int a, int b) {
    return a + b;
}
```
*Compile with: `dmd -shared -fPIC -of=libd_math.so libd_math.d`*

#### Assembly (NASM on System V)
```nasm
; libasm_math.asm
section .text
global asm_add
asm_add:
    mov eax, edi ; Move first argument (edi) into eax
    add eax, esi ; Add second argument (esi) to eax
    ret
```
*Compile with: `nasm -f elf64 libasm_math.asm && gcc -shared -o libasm_math.so libasm_math.o`*

---

## Chapter 6: Calling System Libraries

### Recipe: Calling Native System Libraries

**Problem**: You need to call a native OS library like `user32.dll` on Windows or `libc.so.6` on Linux.

**Solution**: Load the library dynamically, get a function pointer, and use `infix` with the correct signature.

```c
#include <infix/infix.h>
#include <stdio.h>

#if defined(_WIN32)
#include <windows.h>
void run_example() {
    HMODULE user32 = LoadLibraryA("user32.dll");
    void * MessageBoxW_ptr = (void *)GetProcAddress(user32, "MessageBoxW");
    infix_forward_t * t = NULL;
    infix_forward_create(&t, "(*void, *void, *void, uint) -> int");
    // ... call MessageBoxW ...
    infix_forward_destroy(t);
    FreeLibrary(user32);
}
#elif defined(__linux__)
#include <dlfcn.h>
void run_example() {
    void * libm = dlopen("libm.so.6", RTLD_LAZY);
    void * pow_ptr = dlsym(libm, "pow");
    infix_forward_t * t = NULL;
    infix_forward_create(&t, "(double, double) -> double");
    // ... call pow ...
    infix_forward_destroy(t);
    dlclose(libm);
}
#else
void run_example() { printf("No system library example for this platform.\n"); }
#endif

int main() {
    run_example();
    return 0;
}
```

---

## Chapter 7: Memory Management & Performance

### Best Practice: Caching Trampolines

**Rule**: **NEVER** generate a new trampoline for the same function signature inside a hot loop. The performance of `infix` comes from amortizing the one-time generation cost over many fast calls.

```c
// Correct Pattern: Generate once, use many times.
infix_forward_t* t;
infix_forward_create(&t, "(int, int) -> int");
infix_cif_func cif_func = (infix_cif_func)infix_forward_get_code(t);

for (int i = 0; i < 1000000; ++i) {
    // VERY FAST: Re-using the same highly-optimized trampoline.
    cif_func(target, &result, args);
}
infix_forward_destroy(t);
```

---

## Chapter 8: Common Pitfalls & Troubleshooting

### Mistake: Passing a Value Instead of a Pointer in `args[]`
*   **Symptom**: Crash or garbage data.
*   **Explanation**: The `args` array must contain **pointers to** your argument values, not the values themselves.

### Mistake: `infix` Signature Mismatch
*   **Symptom**: Silent data corruption or a crash.
*   **Explanation**: The signature string must *exactly* match the C type's size and alignment. A `long` is 32 bits on 64-bit Windows but 64 bits on 64-bit Linux.
*   **Solution**: Use fixed-width types (`int32`, `uint64`) whenever possible.

### Pitfall: Function Pointer Syntax
*   **Symptom**: Parser error.
*   **Explanation**: A function type is `(...) -> ...`, and a pointer to anything is `*...`. Therefore, a pointer to a function type is `*((...) -> ...)`.
*   **Solution**: `int (*callback)(void)` is `*(() -> int32)`.

---

## Chapter 9: Building Language Bindings

A robust language binding built on `infix` must solve four main challenges.

#### 1. Type Mapping -> Signature String Generation
The binding's primary job is to **generate a signature string** from the high-level language's type information.

#### 2. Trampoline Caching
The binding **must** implement a global, persistent cache for trampolines, using the signature string as the key.

#### 3. Managing Memory & Object Lifetimes
The binding must act as a bridge between the host language's Garbage Collector (GC) and C's manual memory management, holding references to objects to prevent premature collection.

#### 4. Implementing the Callback Bridge
When a C library invokes a reverse trampoline, the JIT-compiled stub calls a C handler. This "bridge" handler must then transfer control back to the high-level language's runtime, often involving acquiring a global lock (like Python's GIL).
