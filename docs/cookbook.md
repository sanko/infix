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
      - [x86-64 (SSE, AVX, and AVX-512)](#x86-64-sse-avx-and-avx-512)
      - [AArch64 (NEON)](#aarch64-neon)
      - [AArch64 (Scalable Vector Extension - SVE)](#aarch64-scalable-vector-extension---sve)
   + [Recipe: Working with Enums](#recipe-working-with-enums)
* [Chapter 3: The Power of Callbacks (Reverse Calls)](#chapter-3-the-power-of-callbacks-reverse-calls)
   + [Recipe: Creating a Type-Safe Callback for `qsort`](#recipe-creating-a-type-safe-callback-for-qsort)
   + [Recipe: Creating a Stateful Callback](#recipe-creating-a-stateful-callback)
* [Chapter 4: Advanced Techniques](#chapter-4-advanced-techniques)
   + [Recipe: Calling Variadic Functions like `printf`](#recipe-calling-variadic-functions-like-printf)
   + [Recipe: Receiving and Calling a Function Pointer](#recipe-receiving-and-calling-a-function-pointer)
   + [Recipe: Calling a Function Pointer from a Struct (V-Table Emulation)](#recipe-calling-a-function-pointer-from-a-struct-v-table-emulation)
   + [Recipe: Handling `long double`](#recipe-handling-long-double)
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
   + [Recipe: Handling Strings and Semantic Types (`wchar_t`, etc.)](#recipe-handling-strings-and-semantic-types-wchar_t-etc)
   + [Recipe: Calling C++ Virtual Functions (V-Table Emulation)](#recipe-calling-c-virtual-functions-v-table-emulation)
   + [Recipe: Bridging C++ Callbacks (`std::function`) and Lambdas](#recipe-bridging-c-callbacks-stdfunction-and-lambdas)
* [Chapter 6: Dynamic Libraries & System Calls](#chapter-6-dynamic-libraries--system-calls)
   + [Recipe: Calling Native System Libraries without Linking](#recipe-calling-native-system-libraries-without-linking)
   + [Recipe: Reading and Writing Global Variables](#recipe-reading-and-writing-global-variables)
      - [Example 1: Simple Integer Variable](#example-1-simple-integer-variable)
      - [Example 2: Aggregate (Struct) Variable](#example-2-aggregate-struct-variable)
   + [Recipe: Handling Library Dependencies](#recipe-handling-library-dependencies)
* [Chapter 7: Introspection for Data Marshalling](#chapter-7-introspection-for-data-marshalling)
   + [Recipe: Creating and Introspecting Semantic Aliases](#recipe-creating-and-introspecting-semantic-aliases)
   + [Recipe: Dynamic Struct Marshalling with the Signature Parser](#recipe-dynamic-struct-marshalling-with-the-signature-parser)
   + [Recipe: Building a Signature String at Runtime](#recipe-building-a-signature-string-at-runtime)
   + [Recipe: Introspecting a Trampoline for a Wrapper](#recipe-introspecting-a-trampoline-for-a-wrapper)
* [Chapter 8: Performance & Memory Management](#chapter-8-performance--memory-management)
   + [Best Practice: Caching Trampolines](#best-practice-caching-trampolines)
   + [Recipe: Using a Custom Arena for a Group of Types](#recipe-using-a-custom-arena-for-a-group-of-types)
   + [Recipe: The Full Manual API Lifecycle (Types to Trampoline)](#recipe-the-full-manual-api-lifecycle-types-to-trampoline)
   + [Recipe: Using Custom Memory Allocators](#recipe-using-custom-memory-allocators)
   + [Recipe: Optimizing Memory with a Shared Arena](#recipe-optimizing-memory-with-a-shared-arena)
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
* [Chapter 12: High-Performance Language Bindings (Direct Marshalling)](#chapter-12-high-performance-language-bindings-direct-marshalling)

---

## Chapter 1: The Basics (Forward Calls)

### Recipe: Calling a Simple C Function

**Problem**: You want to call a standard C function, like `atan2` from the math library.

**Solution**: Describe the function's signature, prepare pointers to your arguments, and invoke the function through a generated trampoline. An "unbound" trampoline is ideal when you want to call multiple functions that share the same signature.

```c
// 1. Describe the signature: double atan2(double y, double x);
const char* signature = "(double, double) -> double";

// 2. Create an unbound trampoline.
infix_forward_t* trampoline = NULL;
infix_forward_create_unbound(&trampoline, signature, NULL);

// 3. Prepare arguments and invoke the call.
double y = 1.0, x = 1.0;
void* args[] = { &y, &x };
double result;
infix_forward_get_unbound_code(trampoline)((void*)atan2, &result, args);
```

> Full example available in [`Ch01_SimpleCall.c`](/eg/cookbook/Ch01_SimpleCall.c).

### Recipe: Passing and Receiving Pointers

**Problem**: You need to call a C function that takes a pointer as an argument and returns a pointer, like `strchr`.

**Solution**: Use the `*` prefix for pointer types. The value in the `args` array for a pointer argument is the address of your pointer variable.

```c
// Signature for: const char* strchr(const char* s, int c);
const char* signature = "(*char, int) -> *char";
infix_forward_t* trampoline = NULL;
infix_forward_create(&trampoline, signature, (void*)strchr, NULL);

// Prepare arguments. The value for the pointer is the address of the char* variable.
const char* haystack = "hello-world";
int needle = '-';
void* args[] = { &haystack, &needle };
const char* result_ptr = NULL;

infix_forward_get_code(trampoline)(&result_ptr, args);
```

> Full example available in [`Ch01_Pointers.c`](/eg/cookbook/Ch01_Pointers.c).

### Recipe: Working with "Out" Parameters

**Problem**: You need to call a C function that doesn't use its return value for its primary output. Instead, it takes a pointer to a variable and writes the result into it. This is a very common pattern for functions that need to return multiple values or an error code.

**Solution**: The signature is straightforward. The "out" parameter is simply a pointer type (`*<type>`). In your calling code, you create a local variable and pass its address in the `args` array.

```c
// bool get_user_stats(int user_id, int* out_posts, double* out_score);
const char* signature = "(int, *int, *double) -> bool";
infix_forward_t* t = NULL;
infix_forward_create(&t, signature, (void*)get_user_stats, NULL);

int user_id = 123;
// These are our "out" variables.
int post_count = 0;
double score = 0.0;
bool success;

// For "out" parameters, the args array contains pointers TO the pointer variables.
int* p_post_count = &post_count;
double* p_score = &score;
void* args[] = { &user_id, &p_post_count, &p_score };

infix_forward_get_code(t)(&success, args);
// After the call, post_count and score are populated.
```

> Full example available in [`Ch01_OutParameters.c`](/eg/cookbook/Ch01_OutParameters.c).

### Recipe: Working with Opaque Pointers (Incomplete Types)

**Problem**: You need to interact with a C library that uses opaque pointers or handles (e.g., `FILE*`, `sqlite3*`) where the internal structure is hidden.

**Solution**: Use the `*void` signature for the handle. For better readability and introspection, create a "semantic alias" for the handle type in a registry. This attaches a meaningful name to the `*void` type without changing how it's handled in the FFI call.

```c
// 1. Use a registry to create a readable, semantic alias for the opaque handle.
infix_registry_t* reg = infix_registry_create();
infix_register_types(reg, "@FileHandle = *void;");

// 2. Create trampolines using the alias. The name @FileHandle is preserved for introspection.
infix_forward_t *t_fopen, *t_fputs, *t_fclose;
infix_forward_create(&t_fopen, "(*char, *char) -> @FileHandle", (void*)fopen, reg);
infix_forward_create(&t_fputs, "(*char, @FileHandle) -> int", (void*)fputs, reg);
infix_forward_create(&t_fclose, "(@FileHandle) -> int", (void*)fclose, reg);

// 3. Use the trampolines in sequence.
void* file_handle = NULL; // This will hold our opaque FILE*
const char* filename = "test.txt", *mode = "w";
infix_forward_get_code(t_fopen)(&file_handle, (void*[]){ &filename, &mode });
// ...
```

> Full example available in [`Ch01_OpaquePointers.c`](/eg/cookbook/Ch01_OpaquePointers.c).

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
// Point move_point(Point p, double dx);
const char* signature = "({double, double}, double) -> {double, double}";
infix_forward_t* trampoline = NULL;
infix_forward_create(&trampoline, signature, (void*)move_point, NULL);

Point start = { 10.0, 20.0 };
double delta_x = 5.5;
void* args[] = { &start, &delta_x };
Point end;

infix_forward_get_code(trampoline)(&end, args);
```

> Full example available in [`Ch02_StructByValue.c`](/eg/cookbook/Ch02_StructByValue.c).

### Recipe: Receiving a Struct from a Function

**Problem**: You need to call a function that *returns* a struct by value.

**Solution**: `infix` handles the ABI details, whether the struct is returned in registers or via a hidden pointer passed by the caller.

```c
// Point make_point(double x, double y);
const char* signature = "(double, double) -> {double, double}";
infix_forward_t* trampoline = NULL;
infix_forward_create(&trampoline, signature, (void*)make_point, NULL);

double x = 100.0, y = 200.0;
void* args[] = { &x, &y };
Point result;

infix_forward_get_code(trampoline)(&result, args);
```

> Full example available in [`Ch02_ReturnStruct.c`](/eg/cookbook/Ch02_ReturnStruct.c).

### Recipe: Large Structs Passed by Reference

**Problem**: A function takes a struct that is too large to fit in registers.

**Solution**: The process is identical to the small struct example. `infix`'s ABI logic will detect that the struct is large and automatically pass it by reference (the standard C ABI rule).

```c
// int get_first_element(LargeStruct s); where LargeStruct is { int data[8]; }
const char* signature = "({[8:int]}) -> int";
infix_forward_t* t = NULL;
infix_forward_create(&t, signature, (void*)get_first_element, NULL);

LargeStruct my_struct = { {123, -1, -1, -1, -1, -1, -1, -1} };
void* args[] = { &my_struct };
int result;

infix_forward_get_code(t)(&result, args);
```

> Full example available in [`Ch02_LargeStruct.c`](/eg/cookbook/Ch02_LargeStruct.c).

### Recipe: Working with Packed Structs

**Problem**: You need to call a function that takes a `__attribute__((packed))` struct.

**Solution**: Use the `!{...}` syntax for 1-byte alignment, or `!N:{...}` to specify a maximum alignment of `N` bytes.

```c
// int process_packed(Packed p); where Packed is #pragma pack(1) { char a; uint64_t b; }
const char* signature = "(!{char, uint64}) -> int";
infix_forward_t* t = NULL;
infix_forward_create(&t, signature, (void*)process_packed, NULL);

Packed p = {'X', 0x1122334455667788ULL};
int result = 0;
void* args[] = {&p};

infix_forward_get_code(t)(&result, args);
```

> Full example available in [`Ch02_PackedStructs.c`](/eg/cookbook/Ch02_PackedStructs.c).

### Recipe: Working with Structs that Contain Bitfields

**Problem**: You need to interact with a C struct that uses bitfields. `infix`'s signature language has no syntax for bitfields because their memory layout is implementation-defined and not portable.

**Solution**: Treat the underlying integer that holds the bitfields as a single member in your signature. Then, use C's bitwise operators in your wrapper code to manually pack and unpack the values before and after the FFI call.

```c
// uint32_t process_bitfields(BitfieldStruct s);
// 1. Describe the struct by its underlying integer storage.
const char* signature = "({uint32}) -> uint32";
infix_forward_t* t = NULL;
infix_forward_create(&t, signature, (void*)process_bitfields, NULL);

// 2. Manually pack the data into a uint32_t.
uint32_t packed_data = 0;
packed_data |= (15 & 0xF) << 0;      // Field a = 15
packed_data |= (1000 & 0xFFF) << 4;  // Field b = 1000
packed_data |= (30000 & 0xFFFF) << 16; // Field c = 30000

// 3. The FFI call sees a simple struct { uint32_t; }.
void* args[] = { &packed_data };
uint32_t result;
infix_forward_get_code(t)(&result, args);
```

> Full example available in [`Ch02_Bitfields.c`](/eg/cookbook/Ch02_Bitfields.c).

### Recipe: Working with Unions

**Problem**: You need to call a function that passes or returns a `union`.

**Solution**: Use the `<...>` syntax to describe the union's members.

```c
// int process_number_as_int(Number n); where Number is union { int i; float f; }
const char* signature = "(<int, float>) -> int";
infix_forward_t* t = NULL;
infix_forward_create(&t, signature, (void*)process_number_as_int, NULL);

Number num_val;
num_val.i = 21;
int result = 0;
void* args[] = {&num_val};

infix_forward_get_code(t)(&result, args);
```

> Full example available in [`Ch02_Unions.c`](/eg/cookbook/Ch02_Unions.c).

### Recipe: Working with Fixed-Size Arrays

**Problem**: A function takes a fixed-size array, like `long long sum(long long arr[4]);`.

**Solution**: In C, an array argument "decays" to a pointer to its first element. The signature must reflect this. To describe the array *itself* (e.g., inside a struct), use the `[N:type]` syntax.

```c
// int64_t sum_array_elements(const int64_t* arr, size_t count);
// Note: Even if the C prototype was `arr[4]`, it decays to a pointer.
const char* signature = "(*sint64, size_t) -> sint64";
infix_forward_t* t = NULL;
infix_forward_create(&t, signature, (void*)sum_array_elements, NULL);

int64_t my_array[] = {10, 20, 30, 40};
const int64_t* ptr_to_array = my_array;
size_t count = 4;
void* args[] = {&ptr_to_array, &count};
int64_t result = 0;

infix_forward_get_code(t)(&result, args);
```

> Full example available in [`Ch02_ArrayDecay.c`](/eg/cookbook/Ch02_ArrayDecay.c).

### Recipe: Advanced Named Types (Recursive & Forward-Declared)

**Problem**: You need to describe complex, real-world C data structures, such as a linked list or mutually dependent types.

**Solution**: The `infix` registry fully supports recursive definitions and forward declarations, allowing you to model these patterns cleanly.

```c
infix_registry_t* registry = infix_registry_create();

// 1. Define types using forward declarations for mutual recursion.
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
```

> Full example available in [`Ch02_AdvancedRegistry.c`](/eg/cookbook/Ch02_AdvancedRegistry.c).

### Recipe: Working with Complex Numbers

**Problem**: You need to call a C function that uses `_Complex` types.

**Solution**: Use the `c[<base_type>]` constructor in the signature string.

```c
// double complex c_square(double complex z);
const char* signature = "(c[double]) -> c[double]";
infix_forward_t* t = NULL;
infix_forward_create(&t, signature, (void*)c_square, NULL);

double complex input = 3.0 + 4.0 * I;
double complex result;
void* args[] = {&input};

infix_forward_get_code(t)(&result, args);
```

> Full example available in [`Ch02_ComplexNumbers.c`](/eg/cookbook/Ch02_ComplexNumbers.c).

### Recipe: Working with SIMD Vectors

**Problem**: You need to call a high-performance C function that uses architecture-specific SIMD vector types for parallel data processing.

**Solution**: Use the generic `v[<elements>:<type>]` syntax or, where available, a convenient keyword alias (like `m512d`). The `infix` ABI logic contains the specific rules for each platform to ensure that these vectors are correctly passed in the appropriate SIMD registers (e.g., XMM/YMM/ZMM on x86-64, V/Z registers on AArch64).

This recipe is broken down by architecture, as the C types and intrinsic functions are platform-specific.

---

#### x86-64 (SSE, AVX, and AVX-512)

This example calls a function that uses AVX-512's 512-bit `__m512d` type to add two vectors of eight `double`s each. The same principle applies to 128-bit SSE (`__m128d`) and 256-bit AVX (`__m256d`) types by simply adjusting the signature.

```c
// __m512d vector_add_512(__m512d a, __m512d b);
// The signature "m512d" is a convenient alias for "v[8:double]".
const char* signature = "(m512d, m512d) -> m512d";
infix_forward_t* t = NULL;
infix_forward_create(&t, signature, (void*)vector_add_512, NULL);

// Prepare arguments using AVX-512 intrinsics.
__m512d a = _mm512_set_pd(8.0, 7.0, 6.0, 5.0, 4.0, 3.0, 2.0, 1.0);
__m512d b = _mm512_set_pd(34.0, 35.0, 36.0, 37.0, 38.0, 39.0, 40.0, 41.0);
void* args[] = {&a, &b};
__m512d result;

infix_forward_get_code(t)(&result, args);
```

> Full example available in [`Ch02_SIMD_AVX.c`](/eg/cookbook/Ch02_SIMD_AVX.c).

---

#### AArch64 (NEON)

This example calls a function that uses ARM NEON's `float32x4_t` type, which is a 128-bit vector of four `float`s.

```c
// float neon_horizontal_sum(float32x4_t vec);
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
```

> Full example available in [`Ch02_SIMD_NEON.c`](/eg/cookbook/Ch02_SIMD_NEON.c).

---

#### AArch64 (Scalable Vector Extension - SVE)

**Problem**: SVE vectors do not have a fixed size; their length is determined by the CPU at runtime. How can we create a trampoline for a function that uses them?

**Solution**: This requires a dynamic, multi-step approach. You must first perform a runtime check for SVE support, then query the CPU's vector length, and finally build the `infix` signature string dynamically before creating the trampoline.

```c
// double sve_horizontal_add(svfloat64_t vec);

// 1. Query the vector length at runtime. svcntd() gets the count of doubles.
size_t num_doubles = svcntd();

// 2. Build the signature string dynamically.
char signature[64];
snprintf(signature, sizeof(signature), "(v[%zu:double]) -> double", num_doubles);

// 3. Create the trampoline with the dynamic signature.
infix_forward_t* t = NULL;
infix_forward_create(&t, signature, (void*)sve_horizontal_add, NULL);

// 4. Prepare arguments and call.
double* data = (double*)malloc(sizeof(double) * num_doubles);
// ... populate data ...
svfloat64_t input_vec = svld1_f64(svptrue_b64(), data);
double result;
infix_forward_get_code(t)(&result, (void*[]){&input_vec});
```

> Full example available in [`Ch02_SIMD_SVE.c`](/eg/cookbook/Ch02_SIMD_SVE.c).

### Recipe: Working with Enums

**Problem**: You need to call a C function that takes an `enum`, but you want to ensure the underlying integer type is handled correctly for ABI purposes.

**Solution**: Use the `e:<type>` syntax in the signature string. `infix` treats the enum identically to its underlying integer type for the FFI call, which is the correct behavior.

```c
// const char* status_to_string(StatusCode code);
// The C `enum` is based on `int`, so we describe it as `e:int`.
const char* signature = "(e:int) -> *char";
infix_forward_t* t = NULL;
infix_forward_create(&t, signature, (void*)status_to_string, NULL);

// Pass the enum value as its underlying integer type.
int code = STATUS_ERR;
const char* result_str = NULL;
void* args[] = { &code };

infix_forward_get_code(t)(&result_str, args);
```

> Full example available in [`Ch02_Enums.c`](/eg/cookbook/Ch02_Enums.c).

---

## Chapter 3: The Power of Callbacks (Reverse Calls)

### Recipe: Creating a Type-Safe Callback for `qsort`

**Problem**: You need to sort an array using C's `qsort`, which requires a function pointer for the comparison logic.

**Solution**: Use `infix_reverse_create_callback`. The handler is a normal, clean C function whose signature exactly matches what `qsort` expects.

```c
// 1. The handler function has a standard C signature.
int compare_integers_handler(const void* a, const void* b) {
    return (*(const int*)a - *(const int*)b);
}

// 2. Create the reverse trampoline.
const char* cmp_sig = "(*void, *void) -> int";
infix_reverse_t* context = NULL;
infix_reverse_create_callback(&context, cmp_sig, (void*)compare_integers_handler, NULL);

// 3. Get the native function pointer and pass it to qsort.
typedef int (*compare_func_t)(const void*, const void*);
compare_func_t my_comparator = (compare_func_t)infix_reverse_get_code(context);

int numbers[] = { 5, 1, 4, 2, 3 };
qsort(numbers, 5, sizeof(int), my_comparator);
```

> Full example available in [`Ch03_QsortCallback.c`](/eg/cookbook/Ch03_QsortCallback.c).

### Recipe: Creating a Stateful Callback

**Problem**: A callback handler needs access to application state, but the C library API is stateless (it has no `void* user_data` parameter).

**Solution**: Use `infix_reverse_create_closure`. This API is specifically designed for stateful callbacks. You provide a generic handler and a `void* user_data` pointer to your state. Inside the handler, you can retrieve this pointer from the `context`.

```c
// 1. The generic handler retrieves state from the context's user_data field.
void my_stateful_handler(infix_context_t* context, void* ret, void** args) {
    AppContext* ctx = (AppContext*)infix_reverse_get_user_data(context);
    int item_value = *(int*)args[0];
    ctx->sum += item_value;
}

// 2. Prepare your state and create the closure, passing a pointer to the state.
AppContext ctx = {"My List", 0};
infix_reverse_t* rt = NULL;
infix_reverse_create_closure(&rt, "(int) -> void", my_stateful_handler, &ctx, NULL);

// 3. Use the generated callback with a C library function.
item_processor_t processor_ptr = (item_processor_t)infix_reverse_get_code(rt);
int list[] = {10, 20, 30};
process_list(list, 3, processor_ptr);
```

> Full example available in [`Ch03_StatefulCallback.c`](/eg/cookbook/Ch03_StatefulCallback.c).

---

## Chapter 4: Advanced Techniques

### Recipe: Calling Variadic Functions like `printf`

**Problem**: You need to call a function with a variable number of arguments.

**Solution**: Use the `;` token to separate fixed and variadic arguments. The signature must exactly match the types you are passing in a *specific call*.

```c
// Signature for: printf(const char* format, int arg1, double arg2);
const char* signature = "(*char; int, double) -> int";
infix_forward_t* trampoline = NULL;
infix_forward_create(&trampoline, signature, (void*)printf, NULL);

const char* fmt = "Count: %d, Value: %.2f\n";
int count = 42;
double value = 123.45;
void* args[] = { &fmt, &count, &value };
int result;

infix_forward_get_code(trampoline)(&result, args);
```

> Full example available in [`Ch04_VariadicPrintf.c`](/eg/cookbook/Ch04_VariadicPrintf.c).

### Recipe: Receiving and Calling a Function Pointer

**Problem**: You need to call a C function that *takes* a function pointer as an argument, and pass it a callback you generate.

**Solution**: The signature for a function pointer is `*((...) -> ...)`. Generate your callback, get its native pointer, and pass that pointer as an argument.

```c
// 1. Create the inner callback.
int multiply_handler(int x) { return x * 10; }
infix_reverse_t* inner_cb_ctx = NULL;
infix_reverse_create_callback(&inner_cb_ctx, "(int)->int", (void*)multiply_handler, NULL);

// 2. Create the outer trampoline for the function that *takes* the callback.
//    Signature for: int harness_func( int(*)(int), int );
const char* harness_sig = "(*((int)->int), int) -> int";
infix_forward_t* harness_trampoline = NULL;
infix_forward_create(&harness_trampoline, harness_sig, (void*)harness_func, NULL);

// 3. Get the native pointer from the callback and pass it as an argument.
void* inner_cb_ptr = infix_reverse_get_code(inner_cb_ctx);
int value = 7;
void* harness_args[] = { &inner_cb_ptr, &value };
int result;

infix_forward_get_code(harness_trampoline)(&result, harness_args);
```

> Full example available in [`Ch04_CallbackAsArg.c`](/eg/cookbook/Ch04_CallbackAsArg.c).

### Recipe: Calling a Function Pointer from a Struct (V-Table Emulation)

**Problem**: You have a pointer to a struct that contains function pointers, similar to a C implementation of an object's v-table. You need to read a function pointer from the struct and then call it.

**Solution**: This is a two-step FFI process. First, read the function pointer value from the struct. Second, create a new trampoline for that function pointer's signature and call it. The Type Registry is perfect for making this clean.

```c
// 1. Define types for the object, function pointers, and v-table.
infix_registry_t* reg = infix_registry_create();
infix_register_types(reg,
    "@Adder = { val: int };"
    "@Adder_add_fn = (*@Adder, int) -> int;"
    "@AdderVTable = { add: *@Adder_add_fn };"
);

// 2. Create an object and get a pointer to its v-table.
Adder* my_adder = create_adder(100);
const AdderVTable* vtable = &VTABLE;

// 3. Read the function pointer from the v-table.
void* add_func_ptr = (void*)vtable->add;

// 4. Create a trampoline for the specific function pointer and call it.
infix_forward_t* t_add = NULL;
infix_forward_create(&t_add, "@Adder_add_fn", add_func_ptr, reg);

int amount_to_add = 23, result;
void* add_args[] = { &my_adder, &amount_to_add };
infix_forward_get_code(t_add)(&result, add_args);
```

> Full example available in [`Ch04_VTableCStyle.c`](/eg/cookbook/Ch04_VTableCStyle.c).

### Recipe: Handling `long double`

**Problem**: You need to call a function that uses `long double`, which has different sizes and ABI rules on different platforms (e.g., 80-bit on x86, 128-bit on AArch64, or just an alias for `double` on MSVC/macOS).

**Solution**: Use the `longdouble` keyword in your signature. `infix`'s ABI logic contains the platform-specific rules to handle it correctly, whether it's passed on the x87 FPU stack (System V x64), in a 128-bit vector register (AArch64), or as a normal `double`.

```c
// long double native_sqrtl(long double x);
const char* signature = "(longdouble) -> longdouble";

infix_forward_t* t = NULL;
infix_forward_create(&t, signature, (void*)native_sqrtl, NULL);

long double input = 144.0L;
long double result = 0.0L;
void* args[] = { &input };

infix_forward_get_code(t)(&result, args);
```

> Full example available in [`Ch04_LongDouble.c`](/eg/cookbook/Ch04_LongDouble.c).

### Recipe: Proving Reentrancy with Nested FFI Calls

**Problem**: You need to be sure that making an FFI call from within an FFI callback is safe.

**Solution**: `infix` is designed to be fully reentrant. The library uses no global mutable state, and all error information is stored in thread-local storage. This recipe demonstrates a forward call that invokes a reverse callback, which in turn makes another forward call.

```c
// 1. Create the innermost forward trampoline (for `multiply`).
infix_forward_t* fwd_multiply = NULL;
infix_forward_create(&fwd_multiply, "(int, int)->int", (void*)multiply, NULL);

// 2. Create the reverse closure, passing the forward trampoline as user_data.
//    The handler will use this trampoline to make the nested call.
infix_reverse_t* rev_nested = NULL;
infix_reverse_create_closure(&rev_nested, "(int)->int", nested_call_handler, fwd_multiply, NULL);

// 3. Create the outermost forward trampoline (for `harness`).
infix_forward_t* fwd_harness = NULL;
const char* harness_sig = "(*((int)->int), int)->int";
infix_forward_create(&fwd_harness, harness_sig, (void*)harness, NULL);

// 4. Execute the call chain.
void* callback_ptr = infix_reverse_get_code(rev_nested);
int base_val = 8;
void* harness_args[] = { &callback_ptr, &base_val };
int final_result;
infix_forward_get_code(fwd_harness)(&final_result, harness_args);
```

> Full example available in [`Ch04_Reentrancy.c`](/eg/cookbook/Ch04_Reentrancy.c).

### Recipe: Proving Thread Safety

**Problem**: You need to create a trampoline in one thread and safely use it in another.

**Solution**: `infix` trampoline handles (`infix_forward_t*` and `infix_reverse_t*`) are immutable after creation and are safe to share between threads. All error state is kept in thread-local storage, so calls from different threads will not interfere with each other.

```c
// Main thread: Create the trampoline.
infix_forward_t* trampoline = NULL;
infix_forward_create(&trampoline, "(int, int)->int", (void*)add, NULL);

// Main thread: Prepare data for the worker thread, including the callable pointer.
thread_data_t data = { infix_forward_get_code(trampoline), 0 };

// Main thread: Spawn a worker thread.
pthread_t thread_id;
pthread_create(&thread_id, NULL, worker_thread_func, &data);

// Worker thread (`worker_thread_func`):
// ...
//   data->cif(&data->result, args); // <-- FFI call happens here
// ...
pthread_join(thread_id, NULL);
```

> Full example available in [`Ch04_ThreadSafety.c`](/eg/cookbook/Ch04_ThreadSafety.c).

---

## Chapter 5: Interoperability with Other Languages

### The Universal Principle: The C ABI

`infix` can call any function that exposes a standard C ABI. Nearly every compiled language provides a mechanism to export a function using this standard (`extern "C"` in C++/Rust/Zig, `//export` in Go, `bind(C)` in Fortran).

### Recipe: Interfacing with a C++ Class (Directly)

**Problem**: You need to call C++ class methods without writing a C wrapper.

**Solution**: Find the compiler-mangled names for the constructor, destructor, and methods. Use `infix` to call them directly, manually passing the `this` pointer as the first argument to methods.

```c
// Mangled names depend on the compiler. This example gets them from a helper.
const char* mangled_ctor = get_mangled_constructor();
const char* mangled_getvalue = get_mangled_getvalue();

// Constructor is: void MyClass(MyClass* this, int val);
infix_forward_create(&t_ctor, "(*void, int)->void", p_ctor, NULL);

// Method is: int getValue(const MyClass* this);
infix_forward_create(&t_getval, "(*void)->int", p_getval, NULL);

// --- Simulate `MyClass* obj = new MyClass(100);` ---
void* obj = malloc(obj_size);
int initial_val = 100;
infix_forward_get_code(t_ctor)(NULL, (void*[]){ &obj, &initial_val });

// --- Simulate `int result = obj->getValue();` ---
int result;
infix_forward_get_code(t_getval)(&result, (void*[]){ &obj });
```

> Full example available in [`Ch05_CppMangledNames.c`](/eg/cookbook/Ch05_CppMangledNames.c) and library source in [`libs/MyClass.cpp`](/eg/cookbook/libs/MyClass.cpp).

### Recipe: Interfacing with C++ Templates

**Problem**: How do you call a C++ function template from C?

**Solution**: You can't call the template itself, but you can call a *specific instantiation* of it. The compiler generates a normal function for each concrete type used with the template, and this function has a predictable mangled name that you can look up and call.

```c
// Mangled name for `Box<double>::get_value()` on GCC/Clang
const char* MANGLED_GET_DBL = "_ZNK3BoxIdE9get_valueEv";

// In a real scenario, you would call the mangled constructor.
// For simplicity here, we manually create the object layout.
double val = 3.14;
void* my_box = malloc(sizeof(double));
memcpy(my_box, &val, sizeof(double));

void* p_get_value = infix_library_get_symbol(lib, MANGLED_GET_DBL);

// Signature: double get_value(const Box<double>* this)
infix_forward_t* t_get = NULL;
infix_forward_create(&t_get, "(*void) -> double", p_get_value, NULL);

double result;
infix_forward_get_code(t_get)(&result, (void*[]){ &my_box });
```

> Full example available in [`Ch05_CppTemplates.c`](/eg/cookbook/Ch05_CppTemplates.c) and library source in [`libs/Box.cpp`](/eg/cookbook/libs/Box.cpp).

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

### Recipe: Handling Strings and Semantic Types (`wchar_t`, etc.)

**Problem**: You are building a language binding and need to introspect a type to marshal data correctly. A signature like `*uint16` is structurally correct for a Windows `wchar_t*`, but how does your code know it's a null-terminated string and not just a pointer to an integer?

**Solution**: Use the `infix` type registry to create **semantic aliases**. The new `infix_type_get_name()` API allows you to retrieve this semantic name at runtime, giving your wrapper the context it needs to perform the correct marshalling logic. This pattern provides the missing link between C's structural type system and the semantic needs of a high-level language.

Let's model the Windows `MessageBoxW` function, which takes two UTF-16 strings.

```c
// 1. Define semantic aliases in a registry.
infix_registry_t* registry = infix_registry_create();
const char* type_defs =
    "@HWND = *void;"
    "@UTF16String = *uint16;" // Represents wchar_t* on Windows
    "@UTF8String = *char;";   // Represents const char*
infix_register_types(registry, type_defs);

// 2. Define function signatures using these aliases.
const char* signature = "(@HWND, @UTF16String, @UTF16String, uint) -> int";

// 3. In your binding, introspect the type to make marshalling decisions.
infix_type_from_signature(&type, &arena, signature, registry);
const infix_type* arg_type = infix_forward_get_arg_type(type, 1);
const char* semantic_name = infix_type_get_name(arg_type); // Will be "UTF16String"

if (semantic_name && strcmp(semantic_name, "UTF16String") == 0) {
    // This is our cue! Marshal the user's string as UTF-16.
}
```

> Full example available in [`Ch05_SemanticStrings.c`](/eg/cookbook/Ch05_SemanticStrings.c).

### Recipe: Calling C++ Virtual Functions (V-Table Emulation)

**Problem**: You have a pointer to a C++ polymorphic base class object (e.g., `Shape*`) and you need to call a `virtual` function on it from C, achieving true dynamic dispatch.

**Solution**: Emulate what the C++ compiler does: manually read the object's v-table pointer (`vptr`), find the function pointer at the correct index within the v-table, and use `infix` to call it.

```c
// 1. Create a C++ object via a factory function.
void* rect_obj = create_rectangle(10.0, 5.0);

// 2. Manually read the v-table pointer from the object's memory.
void** vptr = (void**)rect_obj;
void** vtable = *vptr;

// 3. Read function pointers from their known indices in the v-table.
void* area_fn_ptr = vtable[0]; // double area() const -> index 0
void* name_fn_ptr = vtable[1]; // const char* name() const -> index 1

// 4. Create trampolines for the discovered function pointers.
infix_forward_create(&t_area, "(*void)->double", area_fn_ptr, NULL);
infix_forward_create(&t_name, "(*void)->*char", name_fn_ptr, NULL);

// 5. Call the virtual functions, passing the object as the `this` pointer.
double rect_area;
infix_forward_get_code(t_area)(&rect_area, (void*[]){ &rect_obj });
```

> Full example available in [`Ch05_CppVirtualFunctions.c`](/eg/cookbook/Ch05_CppVirtualFunctions.c) and library source in [`libs/shapes.cpp`](/eg/cookbook/libs/shapes.cpp).

### Recipe: Bridging C++ Callbacks (`std::function`) and Lambdas

**Problem**: You need to call a C++ method that accepts a callback (e.g., `std::function<void(int)>`), and provide a stateful handler from your C application.

**Solution**: This is a powerful, two-way FFI interaction. You will create an `infix` closure to represent your C-side state, and then call a mangled C++ method to register that closure's components (its C function pointer and its state pointer) with the C++ object.

```c
// 1. Create the C-side state and the infix closure.
C_AppState app_state = {0};
infix_reverse_t* closure = NULL;
infix_reverse_create_closure(&closure, "(int, *void)->void", my_closure_handler, &app_state, NULL);

// 2. Create an instance of the C++ EventManager object.
void* manager_obj = malloc(get_size());
infix_forward_create(&t_ctor, "(*void)->void", p_ctor, NULL);
infix_forward_get_code(t_ctor)(NULL, &manager_obj);

// 3. Call the C++ `set_handler` method to register our closure's components.
const char* sig = "(*void, *((int, *void)->void), *void)->void";
infix_forward_create(&t_set_handler, sig, p_set_handler, NULL);
void* closure_c_func = infix_reverse_get_code(closure);
void* closure_user_data = infix_reverse_get_user_data(closure);
void* set_handler_args[] = { &manager_obj, &closure_c_func, &closure_user_data };
infix_forward_get_code(t_set_handler)(NULL, set_handler_args);

// 4. Call the C++ `trigger` method to make it invoke our C callback.
infix_forward_create(&t_trigger, "(*void, int)->void", p_trigger, NULL);
// ...
```

> Full example available in [`Ch05_CppCallbacks.cpp`](/eg/cookbook/Ch05_CppCallbacks.cpp) and library source in [`libs/EventManager.cpp`](/eg/cookbook/libs/EventManager.cpp).

## Chapter 6: Dynamic Libraries & System Calls

### Recipe: Calling Native System Libraries without Linking

**Problem**: You need to call a function from a system library (e.g., `user32.dll`) without linking against its import library at compile time.

**Solution**: Use `infix`'s cross-platform library loading API to get a handle to the library and the function pointer, then create a trampoline.

```c
// 1. Open the system library by name.
infix_library_t* user32 = infix_library_open("user32.dll");

// 2. Look up the address of the `MessageBoxA` function.
void* pMessageBoxA = infix_library_get_symbol(user32, "MessageBoxA");

// 3. Define the signature and create the trampoline.
//    int MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
const char* sig = "(*void, *char, *char, uint32) -> int";
infix_forward_t* t = NULL;
infix_forward_create(&t, sig, pMessageBoxA, NULL);

// 4. Prepare arguments and call the function.
void* hwnd = NULL;
const char* text = "Hello from a dynamically loaded function!";
// ...
int result;
infix_forward_get_code(t)(&result, args);
```

> Full example available in [`Ch06_SystemLibraries.c`](/eg/cookbook/Ch06_SystemLibraries.c).

### Recipe: Reading and Writing Global Variables

**Problem**: You need to access a global variable exported from a shared library, not just a function.

**Solution**: Use `infix_read_global()` and `infix_write_global()`. The powerful signature language is used to describe the variable's type, ensuring `infix` reads or writes the correct number of bytes.

#### Example 1: Simple Integer Variable

```c
infix_library_t* lib = infix_library_open("./libglobals.so");

int counter_val = 0;
// 1. Read the initial value. The signature is simply the type of the variable.
infix_read_global(lib, "global_counter", "int", &counter_val, NULL);

// 2. Write a new value to the global variable.
int new_val = 100;
infix_write_global(lib, "global_counter", "int", &new_val, NULL);

// 3. Read it back to confirm.
infix_read_global(lib, "global_counter", "int", &counter_val, NULL);
```

#### Example 2: Aggregate (Struct) Variable

```c
infix_registry_t* reg = infix_registry_create();
infix_register_types(reg, "@Config = {*char, int};");

Config local_config;
// 1. Read the global struct into our local variable.
infix_read_global(lib, "g_config", "@Config", &local_config, reg);

// 2. Modify and write the struct back to the library.
Config new_config = { "updated", 2 };
infix_write_global(lib, "g_config", "@Config", &new_config, reg);
```

> Full example available in [`Ch06_GlobalVariables.c`](/eg/cookbook/Ch06_GlobalVariables.c) and library source in [`libs/libglobals.c`](/eg/cookbook/libs/libglobals.c).

### Recipe: Handling Library Dependencies

**Problem:** You want to load a library (`libA`) that itself depends on another shared library (`libB`).

**Solution:** You don't have to do anything special. On all modern operating systems, the dynamic linker will automatically find, load, and link `libB` when you load `libA`.

```c
// We only need to open libA. The OS will handle loading libB.
infix_library_t* lib = infix_library_open("./libA.so");

void* p_entry = infix_library_get_symbol(lib, "entry_point_a");
infix_forward_t* t = NULL;
infix_forward_create(&t, "()->int", p_entry, NULL);

int result;
infix_forward_get_code(t)(&result, NULL);
```

> Full example available in [`Ch06_LibraryDependencies.c`](/eg/cookbook/Ch06_LibraryDependencies.c) and library sources in [`libs/libA.c`](/eg/cookbook/libs/libA.c) and [`libs/libB.c`](/eg/cookbook/libs/libB.c).

---

## Chapter 7: Introspection for Data Marshalling

### Recipe: Creating and Introspecting Semantic Aliases

**Problem**: You need to distinguish between types that are structurally identical (like multiple kinds of `void*` handles) for your language binding's marshalling logic.

**Solution**: Use the type registry to create semantic aliases. The `infix_type_get_name()` function allows you to retrieve these names at runtime, providing the context your code needs.

```c
// 1. Define semantic aliases for different handle types.
infix_registry_t* registry = infix_registry_create();
infix_register_types(registry,
    "@DatabaseHandle = *void;"
    "@IteratorHandle = *void;"
    "@MyInt = int32;"
);

// 2. In your binding, parse a type and check its semantic name.
infix_type* type = NULL;
infix_arena_t* arena = NULL;
infix_type_from_signature(&type, &arena, "@DatabaseHandle", registry);

const char* name = infix_type_get_name(type); // name will be "DatabaseHandle"

if (name && strcmp(name, "DatabaseHandle") == 0) {
    // Correctly identified! Now perform database-specific marshalling.
}

// The underlying structural type is still fully accessible.
if (infix_type_get_category(type) == INFIX_TYPE_POINTER) {
    // ...
}
```

> Full example available in [`Ch07_SemanticAliases.c`](/eg/cookbook/Ch07_SemanticAliases.c).

### Recipe: Dynamic Struct Marshalling with the Signature Parser

**Problem**: You have data from a dynamic source (like a script) and need to pack it into a C `struct` layout at runtime.

**Solution**: Use `infix_type_from_signature` to parse a signature into a detailed `infix_type` graph. This graph contains all the `size`, `alignment`, and member `offset` information needed to correctly write data into a C-compatible memory buffer.

```c
void marshal_ordered_data(void* dest, const char* sig, void** src) {
    // 1. Parse the signature to get the struct's layout information.
    infix_type* type = NULL;
    infix_arena_t* arena = NULL;
    infix_type_from_signature(&type, &arena, sig, NULL);

    // 2. Iterate through the struct's members.
    for (size_t i = 0; i < infix_type_get_member_count(type); ++i) {
        const infix_struct_member* member = infix_type_get_member(type, i);
        // 3. Use the offset and size to copy data into the correct location.
        memcpy((char*)dest + member->offset, src[i], infix_type_get_size(member->type));
    }
    infix_arena_destroy(arena);
}
```

> Full example available in [`Ch07_DynamicMarshalling.c`](/eg/cookbook/Ch07_DynamicMarshalling.c).

### Recipe: Building a Signature String at Runtime

**Problem**: The structure of the data you need to work with isn't known until runtime (e.g., it's defined in a configuration file or a user script).

**Solution**: Since `infix` signatures are just strings, you can build them dynamically using `snprintf`. You can then parse this dynamic signature to get layout information, which is perfect for data marshalling or dynamic RPC systems.

```c
// Imagine this data comes from a config file
const char* user_defined_fields[] = { "int", "int", "double" };
int num_fields = 3;

char signature_buffer = "{";
// 1. Build the signature string dynamically.
for (int i = 0; i < num_fields; ++i) {
    strcat(signature_buffer, user_defined_fields[i]);
    if (i < num_fields - 1) strcat(signature_buffer, ",");
}
strcat(signature_buffer, "}"); // Final string is "{int,int,double}"

// 2. Use the dynamic signature to get layout information.
infix_type* dynamic_type = NULL;
infix_arena_t* arena = NULL;
infix_type_from_signature(&dynamic_type, &arena, signature_buffer, NULL);
// ...
```

> Full example available in [`Ch07_DynamicSignatures.c`](/eg/cookbook/Ch07_DynamicSignatures.c).

### Recipe: Introspecting a Trampoline for a Wrapper

**Problem**: You are building a language binding and need to validate the number and types of arguments provided by the user before making an FFI call.

**Solution**: Use the trampoline introspection API to query the signature information stored in the handle.

```c
void dynamic_wrapper(infix_forward_t* trampoline, void* target_func, void** args, size_t num_provided_args) {
    // 1. Introspect the trampoline to get expected argument count.
    size_t num_expected_args = infix_forward_get_num_args(trampoline);

    if (num_provided_args != num_expected_args) {
        fprintf(stderr, "Error: Incorrect number of arguments...\n");
        return;
    }
    // A real binding would also check the types using infix_forward_get_arg_type().

    // 2. Make the call.
    infix_unbound_cif_func cif = infix_forward_get_unbound_code(trampoline);
    cif(target_func, NULL, args);
}
```

> Full example available in [`Ch07_IntrospectWrapper.c`](/eg/cookbook/Ch07_IntrospectWrapper.c).

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
// 1. Create an arena to hold all our type definitions.
infix_arena_t* arena = infix_arena_create(4096);

// 2. Manually define the 'Point' struct type.
infix_struct_member point_members[] = {
    infix_type_create_member("x", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(Point, x)),
    infix_type_create_member("y", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(Point, y))
};
infix_type* point_type = NULL;
infix_type_create_struct(arena, &point_type, point_members, 2);

// 3. Define the argument types for the function.
infix_type* arg_types[] = { point_type, infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE) };

// 4. Create the trampoline using the manually created types.
infix_forward_t* trampoline = NULL;
infix_forward_create_manual(&trampoline, point_type, arg_types, 2, 2, (void*)move_point);
```

> Full example available in [`Ch08_ManualAPI.c`](/eg/cookbook/Ch08_ManualAPI.c).

### Recipe: Using Custom Memory Allocators

**Problem**: Your application uses a custom memory manager for tracking, pooling, or integration with a garbage collector. You need `infix` to use your allocators instead of the standard `malloc`, `calloc`, etc.

**Solution**: `infix` provides override macros (`infix_malloc`, `infix_free`, etc.). Define these macros *before* you include `infix.h` to redirect all of its internal memory operations.

```c
// 1. Define your custom memory management functions.
static void* tracking_malloc(size_t size) { /* ... */ }
static void tracking_free(void* ptr) { /* ... */ }

// 2. Define the infix override macros BEFORE including infix.h
#define infix_malloc(size) tracking_malloc(size)
#define infix_free(ptr)    tracking_free(ptr)

#include <infix/infix.h>

// Now, all calls like infix_forward_create will use your allocators.
infix_forward_create(&trampoline, "()->void", (void*)dummy_func, NULL);
```

> Full example available in [`Ch08_CustomAllocators.c`](/eg/cookbook/Ch08_CustomAllocators.c).

### Recipe: Optimizing Memory with a Shared Arena

**Problem**: Your application creates a large number of trampolines that all reference the same set of complex, named types (e.g., `@Point`, `@User`). By default, `infix` deep-copies the metadata for these types into each trampoline's private memory, leading to high memory consumption and slower creation times.

**Solution**: Use the **shared arena** pattern. By creating the type registry and all related trampolines within a single, user-managed arena, you instruct `infix` to share pointers to the canonical named types instead of copying them. This drastically reduces memory usage and speeds up trampoline creation, but it requires you to manage the lifetime of the shared arena carefully.

**When to use it:** This is an advanced pattern ideal for language runtimes, plugin systems, or long-running applications that create many FFI interfaces referencing a common set of C headers.

```c
#include <infix/infix.h>
#include <stdio.h>
#include <stdint.h>

// Dummy C types and functions to interact with
typedef struct { double x; double y; } Point;
typedef struct { uint64_t id; const char* name; } User;
void handle_point(const Point* p) { /* ... */ }
void handle_user(const User* u) { /* ... */ }

void shared_arena_example() {
    // Create a single, long-lived arena to hold everything.
    infix_arena_t* shared_arena = infix_arena_create(65536);

    // Create the type registry *within* the shared arena.
    infix_registry_t* registry = infix_registry_create_in_arena(shared_arena);

    const char* my_types =
        "@Point = { x: double, y: double };"
        "@User  = { id: uint64, name: *char };";
    infix_register_types(registry, my_types);

    // Create multiple trampolines, also telling them to use the shared arena.
    // Because they share an arena with the registry, the metadata for @Point and
    // @User will be shared via pointers, not deep-copied.
    infix_forward_t *t_point = NULL, *t_user = NULL;
    infix_forward_create_in_arena(&t_point, shared_arena, "(*@Point)->void", (void*)handle_point, registry);
    infix_forward_create_in_arena(&t_user, shared_arena, "(*@User)->void", (void*)handle_user, registry);

    // ... use the trampolines ...

    // The user is responsible for the lifetime of all objects. Destroying the
    // handles and registry first is good practice before freeing the master arena.
    infix_forward_destroy(t_point);
    infix_forward_destroy(t_user);
    infix_registry_destroy(registry);
    infix_arena_destroy(shared_arena);
}
```

> Full, runnable example available in [`Ch08_SharedArena.c`](/eg/cookbook/Ch08_SharedArena.c).

### Recipe: Building a Dynamic Call Frame with an Arena

**Problem**: You are writing a language binding (e.g., for Python, Perl, Lua) and need to build the `void* args[]` array at runtime. The arguments are coming from the host language, so you need to unbox them into temporary C values, create an array of pointers to these temporary values, and then clean everything up after the call. Doing this with `malloc` for every call in a tight loop is inefficient.

**Solution**: Use an `infix` arena to allocate memory for both the unboxed C values *and* the `void**` array that points to them. This makes the entire call frame a single, contiguous block of memory that can be allocated and freed with extreme efficiency.

```c
void dynamic_ffi_call(infix_forward_t* trampoline, ...) {
    // 1. Create a temporary arena for this call's entire data frame.
    infix_arena_t* call_arena = infix_arena_create(4096);

    // 2. Allocate the void** array itself from the arena.
    void** args = infix_arena_alloc(call_arena, sizeof(void*) * arg_count, _Alignof(void*));

    // 3. For each argument, allocate space for its C value in the arena and set the pointer.
    for (int i = 0; i < arg_count; ++i) {
        int* val_ptr = infix_arena_alloc(call_arena, sizeof(int), _Alignof(int));
        *val_ptr = va_arg(va, int); // Get value from dynamic source
        args[i] = val_ptr;
    }

    // 4. Make the FFI call.
    infix_forward_get_unbound_code(trampoline)(target_func, NULL, args);

    // 5. A single free cleans up the void** array AND all the argument values.
    infix_arena_destroy(call_arena);
}
```

> Full example available in [`Ch08_ArenaCallFrame.c`](/eg/cookbook/Ch08_ArenaCallFrame.c).

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
    infix_arena_destroy(arena);
}

// This signature has an invalid character '^' instead of a comma.
report_parse_error("{int, double, ^*char}");
```

> Full example available in [`Ch09_ErrorReporting.c`](/eg/cookbook/Ch09_ErrorReporting.c).

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
int qsort_handler_infix(const void* a, const void* b) {
    return (*(const int*)a - *(const int*)b);
}

// 2. Create the reverse trampoline from a signature.
infix_reverse_t* context = NULL;
infix_reverse_create_callback(&context, "(*void, *void)->int", (void*)qsort_handler_infix, NULL);

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

## Chapter 12: High-Performance Language Bindings (Direct Marshalling)

For advanced language bindings, `infix` offers the **Direct Marshalling API** (`infix_forward_create_direct`). This system moves the unboxing logic (converting host language objects to C values) **inside** the JIT-compiled trampoline, eliminating the need for intermediate `void*` arrays and temporary buffers.

The resulting trampoline is callable with a signature like `void (*)(void* ret, void** objects)`.

```c
// A marshaller for integer objects.
infix_direct_value_t marshal_int(void* obj_ptr) {
    MyLangObject* obj = (MyLangObject*)obj_ptr;
    return (infix_direct_value_t){ .i64 = MyLang_AsInt(obj) };
}

// A marshaller for point structs.
void marshal_point(void* obj_ptr, void* dest, const infix_type* type) {
    MyLangObject* obj = (MyLangObject*)obj_ptr;
    Point* p = (Point*)dest;
    p->x = MyLang_GetFieldDouble(obj, "x");
    p->y = MyLang_GetFieldDouble(obj, "y");
}

// 1. Setup handlers for each argument in the signature.
infix_direct_arg_handler_t handlers[2] = {0};
handlers[0].aggregate_marshaller = marshal_point; // for Point p
handlers[1].scalar_marshaller = marshal_int;      // for int dx

// 2. Create the direct trampoline.
infix_forward_t* trampoline;
infix_forward_create_direct(&trampoline,
    "({double,double}, int) -> void",
    (void*)move_point,
    handlers,
    NULL);

// 3. Call it directly with an array of language objects.
MyLangObject* args[] = { point_obj, int_obj };
infix_direct_cif_func cif = infix_forward_get_direct_code(trampoline);
cif(NULL, (void**)args);
```
