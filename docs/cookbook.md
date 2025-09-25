# The `infix` FFI Cookbook

This guide provides practical, real-world examples to help you solve common FFI problems and leverage the full power of the `infix` library. Where the `README.md` covers concepts, this cookbook provides the code.

> **Note:** All examples in this cookbook are standalone, compilable C files located in the [`eg/cookbook/`](eg/cookbook/) directory.

> For a complete reference on the string format used in these examples (e.g., `"i"`, `"{d,d}"`, `"c*"`), please see the **[Signature Language Reference](docs/signatures.md)**.

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
        *   [Rust](#rust)
        *   [Fortran](#fortran)
        *   [Zig](#zig)
        *   [Go](#go)
        *   [Swift](#swift)
        *   [D (dlang)](#d-dlang)
        *   [Assembly (NASM)](#assembly-nasm)
*   **Chapter 6: Calling System Libraries**
    *   [Recipe: Calling Native System Libraries](#recipe-calling-native-system-libraries)
*   **Chapter 7: Memory Management & Performance**
    *   [Best Practice: Caching Trampolines](#best-practice-caching-trampolines)
*   **Chapter 8: Common Pitfalls & Troubleshooting**
    *   [Mistake: Passing a Value Instead of a Pointer in `args[]`](#mistake-passing-a-value-instead-of-a-pointer-in-args)
    *   [Mistake: `infix` Signature Mismatch](#mistake-infix-signature-mismatch)
    *   [A Note on Memory Safety by Design](#a-note-on-memory-safety-by-design)
*   **Chapter 9: Building Language Bindings**
    *   [The Four Pillars of a Language Binding](#the-four-pillars-of-a-language-binding)

---

## Chapter 1: The Basics (Forward Calls)

### Recipe: Calling a Simple C Function

**Problem**: You want to call a standard C function, like `int add(int, int);`.

**Solution**: Describe the function's signature using the Signature API (`"i,i=>i"`), prepare pointers to your arguments, and invoke the function through the generated trampoline.

```c
#include <infix/infix.h>
#include <stdio.h>

int add_ints(int a, int b) { return a + b; }

int main() {
    infix_forward_t* trampoline = NULL;
    infix_forward_create(&trampoline, "i,i=>i");

    int a = 40, b = 2;
    void* args[] = { &a, &b };
    int result = 0;

    ((infix_cif_func)infix_forward_get_code(trampoline))((void*)add_ints, &result, args);
    printf("Result of add_ints(40, 2) is: %d\n", result);

    infix_forward_destroy(trampoline);
    return 0;
}
```
> [View the full code](eg/cookbook/01_simple_call.c)

### Recipe: Passing and Receiving Pointers

**Problem**: You need to call a C function that takes pointers as arguments, like `void swap(int* a, int* b);`.

**Solution**: Use the `*` modifier in the signature string (`"i*,i*=>v"`). The values you pass in the `args` array are the addresses of your pointer variables.

```c
#include <infix/infix.h>
#include <stdio.h>

void swap_ints(int* a, int* b) {
    int temp = *a; *a = *b; *b = temp;
}

int main() {
    infix_forward_t* trampoline = NULL;
    infix_forward_create(&trampoline, "i*,i*=>v");

    int x = 10, y = 20;
    int* ptr_x = &x;
    int* ptr_y = &y;
    void* args[] = { &ptr_x, &ptr_y };

    printf("Before swap: x = %d, y = %d\n", x, y);
    ((infix_cif_func)infix_forward_get_code(trampoline))((void*)swap_ints, NULL, args);
    printf("After swap: x = %d, y = %d\n", x, y);

    infix_forward_destroy(trampoline);
    return 0;
}
```
> [View the full code](eg/cookbook/02_pointers.c)

### Recipe: Working with Opaque Pointers (Incomplete Types)

**Problem**: You need to interact with a C library that uses opaque pointers (or "handles") where the internal structure is hidden.

**Solution**: Use the `v*` signature for `void*` or any other opaque pointer type. This is the canonical representation for a generic handle.

> [View the full code](eg/cookbook/03_opaque_pointers.c)

### Recipe: Working with Fixed-Size Arrays

**Problem**: You need to call a function that operates on a fixed-size array, like `long long sum_array(long long arr[4]);`.

**Solution**: In C, an array argument "decays" to a pointer to its first element. The signature must reflect this (`"x*=>x"` for `int64_t(const int64_t*)`). `infix` will handle the call correctly.

> [View the full code](eg/cookbook/04_fixed_arrays.c)

---

## Chapter 2: Handling Complex Data Structures

### Recipe: Dynamic Struct Marshalling with the Signature Parser

**Problem**: You have data from a dynamic source (e.g., a script) and need to pack it into a C `struct` layout at runtime.

**Solution**: Use `infix_type_from_signature` to parse a signature string into a detailed `infix_type` graph. This graph contains all the `size`, `alignment`, and member `offset` information needed to correctly write data into a C-compatible memory buffer.

> [View the full code](eg/cookbook/05_dynamic_marshalling.c)

### Recipe: Small Structs Passed by Value

**Problem**: You need to call a function that takes a small `struct` that the ABI passes in registers.

**Solution**: Use the `{}` syntax (e.g., `"{d,d}=>d"` for `double(Point)`). `infix` will automatically determine the correct ABI passing convention.

> [View the full code](eg/cookbook/06_small_struct_by_value.c)

### Recipe: Large Structs Passed by Reference

**Problem**: A function takes a struct that is too large to fit in registers.

**Solution**: The process is identical to the small struct example. `infix`'s ABI logic will detect that the struct is large and automatically pass it by reference.

> [View the full code](eg/cookbook/07_large_struct_by_reference.c)

### Recipe: Receiving a Struct from a Function

**Problem**: You need to call a function that *returns* a struct by value.

**Solution**: Simply use the struct signature as the return type (e.g., `"=>__{d,d_}_"`).

> [View the full code](eg/cookbook/08_return_struct.c)

### Recipe: Working with Packed Structs via the Signature API

**Problem**: You need to call a C function that takes a packed struct.

**Solution**: Use the `p(size,align){type@offset,...}` signature syntax, providing the exact layout metadata from your C compiler using `sizeof`, `_Alignof`, and `offsetof`.

> [View the full code](eg/cookbook/09_packed_struct.c)

### Recipe: Working with Unions

**Problem**: You need to call a function that passes or returns a `union`.

**Solution**: Use the `<...>` syntax to describe the union (e.g., `"<i,f>=>i"`). `infix` will automatically classify it for ABI compliance.

> [View the full code](eg/cookbook/10_unions.c)

### Recipe: Working with Pointers to Arrays

**Problem**: You need to call a function that takes a pointer to a fixed-size array, like `void process_matrix(int (*matrix)[4]);`.

**Solution**: Use grouping parentheses `()` around the array type before adding the `*` pointer modifier (e.g., `"([4]i)*=>v"`).

> [View the full code](eg/cookbook/11_pointer_to_array.c)

---

## Chapter 3: The Power of Callbacks (Reverse Calls)

### Recipe: Creating a Stateless Callback for `qsort`

**Problem**: You need to sort an array using C's `qsort`, which requires a function pointer for the comparison logic.

**Solution**: Use a reverse trampoline to create a native function pointer for your comparison handler. The handler's signature must accept `infix_context_t*` as its first argument.

> [View the full code](eg/cookbook/12_callback_qsort.c)

### Recipe: Creating a Stateful Callback (The Modern Way)

**Problem**: A callback handler needs access to application state, but the C library API is stateless (it provides no `void* user_data` parameter).

**Solution**: `infix` automatically passes a pointer to the `infix_context_t` as the **first argument** to every C callback handler. Retrieve your application state from the context's `user_data` field.

> [View the full code](eg/cookbook/13_stateful_callback.c)

## Chapter 4: Advanced Techniques

### Recipe: Calling Variadic Functions like `printf`

**Problem**: You need to call a function with a variable number of arguments.

**Solution**: Provide the types for *all* arguments you intend to pass in a single call and use a semicolon (`;`) in the signature to mark where the variadic part begins.

> [View the full code](eg/cookbook/14_variadic_printf.c)

### Recipe: Creating a Variadic Callback

**Problem**: You need to create a native function pointer for a handler that is itself variadic.

**Solution**: Your C handler will use `<stdarg.h>`. The `infix` signature must describe a specific, concrete instance of the variadic call you expect the C code to make.

> [View the full code](eg/cookbook/15_variadic_callback.c)

### Recipe: Proving Reentrancy with Nested FFI Calls

**Problem**: You need to call a C function that takes a callback, and inside that callback handler, you need to call *another* C function using `infix`.

**Solution**: `infix` is fully reentrant. Create all necessary trampolines upfront and use them as needed.

> [View the full code](eg/cookbook/16_nested_calls.c)

### Recipe: Receiving and Calling a Function Pointer

**Problem**: You need to call a factory function that returns a pointer to another function, which you then need to call.

**Solution**: Use two reverse trampolines. The "provider" callback returns a pointer to the "worker" callback, which it retrieves from its `user_data`.

> [View the full code](eg/cookbook/17_return_callback.c)

---

## Chapter 5: Interoperability with Other Languages

### The Universal Principle: The C ABI

It is possible to call a function written in Rust, Fortran, or C++ from C because of a shared standard: the **C Application Binary Interface (ABI)**. Nearly every compiled language provides a mechanism to expose a function using the C ABI. Once you have a C-compatible function pointer, the process of creating and using an `infix` trampoline is **exactly the same**, regardless of the source language.

### Recipe: Interfacing with a C++ Class

**Problem**: You need to create, use, and destroy a C++ object from a pure C environment.

**Solution**: The most robust solution is to create a simple C-style API in your C++ code using `extern "C"`. `infix` can then call this clean, predictable API, using `v*` as the opaque handle for the object pointer.

> [View the full code](eg/cookbook/18_cpp_example.c)
The Pattern for Other Compiled Languages

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

    infix_forward_t* trampoline = NULL;
    infix_forward_create(&trampoline, "i,i=>i");

    int a = 50, b = 50;
    void* args[] = { &a, &b };
    int result = 0;

    ((infix_cif_func)infix_forward_get_code(trampoline))((void*)rust_add, &result, args);

    printf("Result from Rust: %d\n", result); // Expected: 100

    infix_forward_destroy(trampoline);
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
    infix_forward_t* trampoline = NULL;
    infix_forward_create(&trampoline, "i,i=>i");

    int a = 20, b = 22;
    void* args[] = { &a, &b };
    int result = 0;

    ((infix_cif_func)infix_forward_get_code(trampoline))((void*)fortran_add, &result, args);

    printf("Result from Fortran: %d\n", result); // Expected: 42

    infix_forward_destroy(trampoline);
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

## Chapter 6: Calling System Libraries

### Recipe: Calling Native System Libraries

**Problem**: You need to call a native OS library like `User32.dll` on Windows or `CoreFoundation.framework` on macOS.

**Solution**: Load the library dynamically, get a function pointer, and use `infix` with the correct signature. The example file contains platform-specific code for Windows, macOS, and Linux.

> [View the full code](eg/cookbook/19_system_libraries.c)

---

## Chapter 7: Memory Management & Performance

### Best Practice: Caching Trampolines

**Rule**: **NEVER** generate a new trampoline for the same function signature inside a hot loop. The performance of `infix` comes from amortizing the one-time generation cost over many fast calls.

```c
// Anti-pattern: DO NOT DO THIS!
for (int i = 0; i < 1000000; ++i) {
    infix_forward_t* t;
    // VERY SLOW: Generating a new trampoline on every iteration.
    infix_forward_create(&t, "i,i=>i");
    cif_func(target, &result, args);
    infix_forward_destroy(t);
}
```

By amortizing the one-time generation cost over millions of calls, the FFI overhead becomes negligible.

```c
// Correct Pattern: Generate once, use many times.
infix_forward_t* t;
infix_forward_create(&t, "i,i=>i");
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

*   **Symptom**: Immediate crash (segmentation fault) or garbage data.
*   **Explanation**: The `args` array must contain **pointers to** your argument values, not the values themselves.

### Mistake: `infix` Signature Mismatch

*   **Symptom**: Silent data corruption or a crash much later in execution.
*   **Explanation**: The type you describe in the signature string must *exactly* match the C type's size and alignment. A common error is mismatching the `long` type, which is 32 bits on 64-bit Windows but 64 bits on 64-bit Linux.
*   **Solution**: Use fixed-width types from `<stdint.h>` (e.g., `int64_t`) and their corresponding `infix` types (`x`) whenever possible.

### A Note on Memory Safety by Design

The `infix` API is designed to eliminate common C memory management errors.
*   The high-level Signature API (`infix_forward_create`, etc.) handles all `infix_type` memory management **automatically**.
*   The low-level Manual API (`infix_type_create_struct`, etc.) is now **exclusively arena-based**, forcing a safe memory model where all types are freed with a single call to `infix_arena_destroy`.

---

## Chapter 9: Building Language Bindings

**Discussion**: `infix` is an ideal engine for creating a "language binding"—a library that allows a high-level language like Python, Ruby, or Lua to call C functions. The binding provides the crucial "glue" to the high-level language's runtime.

### The Four Pillars of a Language Binding

A robust language binding built on `infix` must solve four main challenges.

#### 1. Type Mapping -> Signature String Generation

Instead of building complex C `infix_type` objects, the binding's primary job is to **generate a signature string** from the high-level language's type information. This is a much simpler string manipulation task.

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
static std::map<std::string, infix_forward_t*> g_trampoline_cache;

infix_forward_t* get_or_create_trampoline(const char* signature) {
    if (g_trampoline_cache.count(signature)) {
        return g_trampoline_cache[signature];
    }
    infix_forward_t* new_trampoline = NULL;
    if (infix_forward_create(&new_trampoline, signature) == INFIX_SUCCESS) {
        g_trampoline_cache[signature] = new_trampoline;
    }
    return new_trampoline;
}
```

#### 3. Managing Memory & Object Lifetimes

This is often the hardest part of FFI. The high-level language has a garbage collector (GC), but C does not. The binding must act as a bridge.

*   **For Forward Calls (HLL -> C)**: When passing an object like a string to C, the binding must **hold a reference** to the high-level object for the duration of the C call to prevent the GC from collecting its memory.
*   **For Reverse Calls (C -> HLL)**: When a high-level function is passed to C as a callback, the binding must store a **handle to the HLL function object** in the `user_data` field of the reverse trampoline. When the trampoline is destroyed, the binding must release its reference, allowing the GC to collect it.

#### 4. Implementing the Callback Bridge

When a C library invokes a reverse trampoline, the JIT-compiled stub calls a C handler. This "bridge" handler must then transfer control back to the high-level language's runtime.

**Conceptual Python Callback Bridge:**

```c
#include <Python.h> // Example for Python

// This C function is the handler given to infix. Its signature includes the
// implicit context pointer, followed by the arguments from the signature string.
void python_callback_bridge(infix_context_t* context, /* arg1, arg2, ... */) {
    PyGILState_STATE gstate = PyGILState_Ensure(); // 1. Acquire the GIL.

    // 2. Get the Python function handle from user_data via the context.
    PyObject* py_callback = (PyObject*)infix_reverse_get_user_data(context);

    // 3. Convert the C arguments into a Python tuple.
    PyObject* py_args = convert_c_args_to_python_tuple(/* ... */);

    // 4. Call the Python function.
    PyObject* py_result = PyObject_CallObject(py_callback, py_args);

    if (py_result != NULL) {
        // 5. Convert the Python result back to C and store it in the return buffer.
        //    The bridge would need access to the return buffer pointer, which it
        //    would typically receive from the dispatcher.
        convert_python_result_to_c(py_result, /* ... */);
        Py_DECREF(py_result);
    }
    else
        PyErr_Print(); // Handle exceptions.

    Py_DECREF(py_args);
    PyGILState_Release(gstate); // 6. Release the GIL.
}
```

---

# License and Legal

Copyright (c) 2025 Sanko Robinson

This documentation is licensed under the Creative Commons Attribution 4.0 International License (CC BY 4.0). You are free to share and adapt this material for any purpose, provided you give appropriate credit.

For the full license text, see the [LICENSE-CC](/LICENSE-CC) file or visit [https://creativecommons.org/licenses/by/4.0/](https://creativecommons.org/licenses/by/4.0/).
