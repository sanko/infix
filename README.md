# infix: A Lightweight FFI Code Generation Library for C

**infix** is a minimal, dependency-free, Just-in-Time (JIT) powered Foreign Function Interface (FFI) library for modern C. It allows you to dynamically create function calls and callbacks at runtime by generating machine code on the fly.

The entire project is written from scratch in C17 and serves as a practical example of how low-level code generation, ABI-specific logic, and memory management work together.

### Features

*   **Convenient String-Based API**: Define complex C function signatures, including packed structs and function pointers, using a simple, human-readable string.
*   **Forward Calls:** Dynamically generate and call any C function pointer, even for functions with complex signatures and variadic arguments.
*   **Reverse Calls (Callbacks):** Generate native, callable C function pointers that wrap a custom handler function. The callback mechanism is **thread-safe**, re-entrant, and supports variadic function signatures.
*   **Cross-Platform & Cross-Compiler ABI Support:** Correctly handles calling conventions across multiple platforms and compilers:
    *   **x86-64:** System V (Linux, macOS, BSD) and Windows x64 (MSVC, GCC, and Clang).
    *   **ARM64 (AArch64):** AAPCS64 (Linux, macOS, Windows, BSD), including correct handling of Apple-specific variadic rules.
*   **Rich Type System:** Supports a comprehensive set of C types, including primitives, pointers, structs, unions, and fixed-size arrays.
*   **Performance Optimized:** The one-time cost of trampoline generation is significantly accelerated by an internal arena allocator, which replaces thousands of small `malloc` calls with simple pointer bumps.
*   **Secure by Design:** Adheres to strict security principles, validated through extensive testing:
    *   **W^X (Write XOR Execute):** Enforces that memory is never writable and executable at the same time.
    *   **Overflow Hardened:** The type system is protected against integer overflows from malformed or malicious user input.
    *   **Use-After-Free Protection:** Freed trampolines are converted into guard pages, ensuring calls to dangling pointers result in a safe, immediate crash.
    *   **Read-Only Contexts:** Callback context data is made read-only after creation to protect against runtime memory corruption attacks.
*   **Simple Integration**: Add `infix.h` to your includes and compile with your project to get started.

## API Quick Reference

infix provides two API layers: a convenient high-level Signature API and a powerful low-level Core API.

#### 1. The Signature API

This API uses simple strings to define function signatures, making it easy to use and read.

```c
#include <infix.h>

// Generate a forward trampoline for `int add(int, int)`
ffi_trampoline_t* t;
ffi_create_forward_trampoline_from_signature(&t, "ii => i");

// Generate a reverse trampoline (callback) for `void handler(char*)`
ffi_reverse_trampoline_t* rt;
ffi_create_reverse_trampoline_from_signature(&rt, "c* => v", my_handler, NULL);
```

#### 2. The Core API (Recommended for Advanced Control)

This API gives you fine-grained control by requiring you to build type descriptions manually. It's more verbose but powerful for programmatically constructing types.

```c
#include <infix.h>

// Describe the signature `int(int, int)` manually
ffi_type* ret_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32);
ffi_type* arg_types[] = { ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32),
                          ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32) };

// Generate the trampoline
ffi_trampoline_t* t;
generate_forward_trampoline(&t, ret_type, arg_types, 2, 2);
```

## Getting Started Example

This example uses the **Signature API** to call the standard C `printf` function.

```c
#include <infix.h>
#include <stdio.h>

int main(void) {
    // 1. Describe the function signature as a string.
    // Signature: int printf(const char* format, ...);
    // We will call it with an int and a double.
    // 'c*' = const char*, '.' = variadic separator, 'i' = int, 'd' = double
    const char* signature = "c*.id => i";

    // 2. Generate the trampoline from the signature.
    ffi_trampoline_t* trampoline = NULL;
    ffi_status status = ffi_create_forward_trampoline_from_signature(&trampoline, signature);
    if (status != FFI_SUCCESS) return 1;

    // 3. Prepare the arguments.
    const char* format_str = "Hello! The number is %d and the double is %.2f\n";
    int my_int = 42;
    double my_double = 3.14;
    void* args[] = { &format_str, &my_int, &my_double };

    // 4. Get the callable function pointer and invoke it.
    ffi_cif_func cif_func = (ffi_cif_func)ffi_trampoline_get_code(trampoline);
    int printf_ret = 0;
    cif_func((void*)printf, &printf_ret, args);

    printf("printf returned: %d\n", printf_ret);

    // 5. Clean up.
    ffi_trampoline_free(trampoline);
    return 0;
}
```

## Signature Language Reference

The signature string is a powerful mini-language for describing C types. The format is `arg1_type arg2_type ... => return_type`.

### Primitives

| Code | C Type                 |
| :--- | :--------------------- |
| `v`  | `void`                 |
| `b`  | `bool`                 |
| `a`  | `signed char`          |
| `c`  | `char`                 |
| `h`  | `unsigned char`        |
| `s`  | `short`                |
| `t`  | `unsigned short`       |
| `i`  | `int`                  |
| `j`  | `unsigned int`         |
| `l`  | `long`                 |
| `m`  | `unsigned long`        |
| `x`  | `long long`            |
| `y`  | `unsigned long long`   |
| `n`  | `__int128_t`           |
| `o`  | `__uint128_t`          |
| `f`  | `float`                |
| `d`  | `double`               |
| `e`  | `long double`          |

### Composites

| Syntax                                     | C Equivalent                                     |
| ------------------------------------------ | ------------------------------------------------ |
| `T*`                                       | `T*` (e.g., `i*` is `int*`)                     |
| `T**`                                      | `T**` (e.g., `c**` is `char**`)                 |
| `T[N]`                                     | `T[N]` (e.g., `f[16]` is `float[16]`)           |
| `{member1;member2}`                        | `struct { T1 member1; T2 member2; }`             |
| `<member1;member2>`                        | `union { T1 member1; T2 member2; }`              |
| `p(size,align){type1:off1;...}`             | A packed struct with explicit layout             |
| `(args...=>ret)`                           | A function pointer, e.g., `(i=>v)` for `void (*)(int)` |

### Delimiters

| Delimiter | Purpose                                                     |
| :-------- | :---------------------------------------------------------- |
| `=>`      | **Required.** Separates arguments from the return type.     |
| `.`       | **Optional.** Separates fixed arguments from variadic ones. |
| `;`       | **Required.** Separates members inside `{...}` and `<...>` lists. |
| `:`       | **Required.** Separates type from offset in packed structs. |

### Examples

| Signature String                 | Corresponding C Function Signature                               |
| -------------------------------- | ------------------------------------------------------------------ |
| `ii => i`                        | `int function(int, int);`                                        |
| `c* => v`                        | `void function(char*);` (Also used for `void*`)                  |
| `(i=>v) => v`                    | `void function(void (*callback)(int));`                          |
| `{i;f}c* => v`                   | `void function(struct { int a; float b; }, char*);`               |
| `c*.if => i`                     | `int function(const char*, int, float, ...);`                     |
| `p(9,1){c:0;y:1} => i`           | `int function(PackedStruct);` (where `PackedStruct` is `char a; uint64_t b;` packed to 1-byte alignment) |


### Project Structure

```.
├── include/              # Public API header (infix.h) and compatibility headers
├── src/                  # All implementation files
│   ├── arch/             # Architecture-specific implementations (x64, aarch64)
│   └── core/             # Core implementation files (executor.c, types.c, etc.)
├── t/                    # Test files
├── fuzz/                 # Fuzzing harness
├── docs/                 # Detailed documentation
│   ├── cookbook.md       # Practical recipes and examples
│   └── internals.md      # Deep dive into the architecture
└── README.md             # This file
```

### API Concepts

The infix API is built around a few core concepts. Understanding them is key to using the library effectively.

#### 1. The Type System (`ffi_type`)

Before you can call a function or create a callback, you must describe its signature to the library. This is done using `ffi_type` pointers.

*   **Static Types:** For basic C types, you use singleton instances provided by the library. You **never** need to free these.
    *   `ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32)` for `int`.
    *   `ffi_type_create_pointer()` for any pointer type (`char*`, `void*`, `MyStruct*`).
    *   `ffi_type_create_void()` for functions that return `void`.
*   **Dynamic Types:** For complex types like structs, unions, and arrays, you must build them dynamically. These **must** be freed with `ffi_type_destroy` when you are done with them.
    *   `ffi_type_create_struct()`: Takes an array of `ffi_struct_member` that describes the layout of the struct.
    *   `ffi_type_create_array()`: Describes a fixed-size array of another `ffi_type`.

#### 2. Forward Calls (`generate_forward_trampoline`)

A "forward call" is when your code calls a C function. To do this, you generate a **trampoline**. A trampoline is a small, JIT-compiled function stub that bridges the gap between the library's generic calling convention and the target function's specific, native ABI.

The process is:
1.  Describe the function's return type and argument types using an array of `ffi_type*`.
2.  Call `generate_forward_trampoline()` with this signature.
3.  This returns a `ffi_trampoline_t*` handle. Get the executable code pointer from it by calling `ffi_trampoline_get_code()`.
4.  Cast this pointer to `ffi_cif_func`.
5.  Call the `ffi_cif_func`, passing it the target function's address, a pointer to a buffer for the return value, and an array of pointers to the arguments.
6.  Free the trampoline with `ffi_trampoline_free()`.

#### 3. Reverse Calls / Callbacks (`generate_reverse_trampoline`)

A "reverse call" is when you create a native C function pointer that, when called by external code, executes a C function handler that you provide. This is used to implement callbacks.

The process is:
1.  Describe the desired signature of your callback using `ffi_type*`.
2.  Call `generate_reverse_trampoline()`, passing it the signature, a pointer to your C handler function, and an optional `void* user_data` pointer to maintain state.
3.  This returns a `ffi_reverse_trampoline_t*` handle.
4.  The native function pointer is located in `rt->exec_code.rx_ptr`. Cast this pointer to the appropriate function pointer type.
5.  You can now pass this function pointer to any C API that expects a callback.
6.  The `ffi_reverse_trampoline_t*` handle **must** remain alive for as long as the native function pointer is in use. Free it with `ffi_reverse_trampoline_free()` when the callback is no longer needed.

#### 4. Error Handling (`ffi_status`)

Nearly all API functions that can fail return an `ffi_status` enum. Always check the return value of these functions.

```c
ffi_trampoline_t* trampoline = NULL;
ffi_status status = generate_forward_trampoline(&trampoline, ...);
if (status != FFI_SUCCESS) {
    // Handle the error
}
```

#### 5. Memory Management

*   **If you `create` it, you `destroy` it.** Any `ffi_type` from `ffi_type_create_struct`, `_union`, or `_array` must be freed with `ffi_type_destroy()`. Destruction is recursive.
*   **The caller owns input on failure.** If `ffi_type_create_struct` fails, you are still responsible for freeing the `members` array you passed in.
*   **Do not free static types.** Return values from `ffi_type_create_primitive()`, `_pointer()`, and `_void()` must not be destroyed.
*   **Trampolines must be freed.** Always call `ffi_trampoline_free()` and `ffi_reverse_trampoline_free()`.

### How It Works

`infix` generates raw machine code at runtime and writes it into a W^X executable memory block.

1.  **ABI Specification:** An `ffi_abi_spec` v-table provides function pointers to an implementation for the target ABI.
2.  **Trampoline Generation:** The library consults the ABI spec to create a `ffi_call_frame_layout` blueprint that maps each argument to its destination (register or stack).
3.  **JIT Execution:** The core engine uses this blueprint to emit machine code into a memory buffer, which is then made executable using platform-specific APIs.

For a deeper dive into the architecture, see [docs/internals.md](./docs/internals.md).

### Example 1: Forward Call (Calling a C function)

This example shows how to dynamically call the function `int add(int a, int b)`.

```c
#include "infix.h"
#include <stdio.h>

// The C function we want to call
int add(int a, int b) {
    return a + b;
}

int main(void) {
    // 1. Describe the function signature as a string.
    // Signature: int printf(const char* format, ...);
    // We will call it with an int and a double.
    // 'c*' = const char*, '.' = variadic separator, 'i' = int, 'd' = double
    const char* signature = "c*.id => i";

    // 2. Generate the trampoline from the signature.
    ffi_trampoline_t* trampoline = NULL;
    ffi_status status = ffi_create_forward_trampoline_from_signature(&trampoline, signature);

    if (status != FFI_SUCCESS) {
        fprintf(stderr, "Failed to generate trampoline from signature.\n");
        return 1;
    }

    // 3. Prepare the arguments.
    const char* format_str = "Hello from a signature! The number is %d and the double is %.2f\\n";
    int my_int = 42;
    double my_double = 3.14;
    void* args[] = { &format_str, &my_int, &my_double };

    // 4. Get the callable function pointer and invoke it.
    ffi_cif_func cif_func = (ffi_cif_func)ffi_trampoline_get_code(trampoline);
    int printf_ret = 0;
    cif_func((void*)printf, &printf_ret, args);

    printf("printf returned: %d\\n", printf_ret);

    // 5. Clean up.
    ffi_trampoline_free(trampoline);
    return 0;
}
```

### Example 2: Calling a Variadic Function

Calling a function like `snprintf` requires specifying how many arguments are part of the fixed signature before the `...`. For `snprintf(buf, size, format, ...)`, there are 3 fixed arguments.

```c
#include "infix.h"
#include <stdio.h>
#include <string.h>

void test_variadic_call() {
    // Target signature: int snprintf(char*, size_t, const char*, ...);
    ffi_type* ret_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32);
    ffi_type* arg_types[] = {
        ffi_type_create_pointer(),                             // Fixed: char* buffer
        ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_UINT64),  // Fixed: size_t size
        ffi_type_create_pointer(),                             // Fixed: const char* format
        ffi_type_create_pointer(),                             // Variadic: const char* "hello"
        ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32),  // Variadic: int 123
        ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_DOUBLE)   // Variadic: double 3.14
    };

    // Generate the trampoline: Total arguments = 6. Fixed arguments = 3.
    ffi_trampoline_t* trampoline = NULL;
    ffi_status status = generate_forward_trampoline(&trampoline, ret_type, arg_types, 6, 3);
    if (status != FFI_SUCCESS) {
        fprintf(stderr, "Failed to generate variadic trampoline: %d\n", status);
        return;
    }
    ffi_cif_func cif_func = (ffi_cif_func)ffi_trampoline_get_code(trampoline);

    char buffer;
    size_t buf_size = sizeof(buffer);
    const char* format = "Variadic call: %s %d %.2f";
    const char* str_arg = "hello";
    int int_arg = 123;
    double dbl_arg = 3.14;
    void* args[] = { &buffer, &buf_size, &format, &str_arg, &int_arg, &dbl_arg };
    int chars_written = 0;

    cif_func((void*)snprintf, &chars_written, args);
    printf("'%s' (%d chars)\n", buffer, chars_written); // Prints "'Variadic call: hello 123 3.14' (31 chars)"

    ffi_trampoline_free(trampoline);
}
```

### Example 3: Reverse Call (Creating a Callback)

This example creates a C function pointer that, when called, will execute our `my_int_callback_handler`.

```c
#include "infix.h"
#include <stdio.h>

// Our custom handler that will be called by the trampoline
int my_int_callback_handler(int a, int b) {
    return a * b;
}

void test_reverse_call() {
    // 1. Describe the signature of the callback
    ffi_type *ret_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32);
    ffi_type *arg_types[] = {
        ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32),
        ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32)
    };

    // 2. Generate the reverse trampoline, linking it to our handler.
    ffi_reverse_trampoline_t *rt = NULL;
    ffi_status status = generate_reverse_trampoline(
        &rt, ret_type, arg_types, 2, 2, (void *)my_int_callback_handler, NULL
    );
    if (status != FFI_SUCCESS) {
        fprintf(stderr, "Failed to generate reverse trampoline: %d\n", status);
        return;
    }

    // 3. Get a native, callable function pointer from the trampoline
    typedef int (*my_func_ptr)(int, int);
    my_func_ptr func_ptr = (my_func_ptr)rt->exec_code.rx_ptr;

    // 4. Call the generated pointer as if it were a normal C function
    int result = func_ptr(7, 6);
    printf("Result of callback(7, 6): %d\n", result); // Prints 42

    // 5. Clean up
    ffi_reverse_trampoline_free(rt);
}
```

### Building the Project

**Prerequisites:**
*   A C17-compatible compiler like GCC, Clang, or MSVC.
*   `perl` (recommended, cross-platform).

#### Using Perl

The included Perl script can build the library, run tests, and manage other tasks.

```bash
# Seek help
perl build.pl help

# Build the static library (libinfix.a or infix.lib)
perl build.pl build

# To specify a compiler (msvc, gcc, clang):
perl build.pl --compiler=clang build

# Run all standard tests
perl build.pl test

# Run the memory stress test under Valgrind (on Linux)
perl build.pl memtest

# Run the fault injection memory test under Valgrind (on Linux)
perl build.pl memtest:fault

# Run the threading test with ThreadSanitizer (on a compatible toolchain)
perl build.pl test 800_threading

# Build and run the fuzzer (requires Clang)
perl build.pl fuzz
./fuzz_types_harness -max_total_time=300 corpus/
```

### Integrating infix Into Your Project

To use infix in your own application:

1.  Run `perl build.pl build` to produce the static library (`libinfix.a` or `infix.lib`).
2.  Copy the static library and the `include/` directory into your project's source tree.
3.  Include the main header in your code: `#include "infix.h"`
4.  When compiling your application, tell the compiler where to find the header files and how to link the library.

**Example GCC/Clang link command:**
```bash
gcc src/main.c -Ipath/to/infix/include -Lpath/to/infix/lib -linfix -o my_app
```

### Learn More

*   **[Cookbook](./docs/cookbook.md):** Practical, copy-pasteable recipes for common FFI tasks.
*   **[Internals](./docs/internals.md):** A deep dive into the library's architecture for maintainers and contributors.
*   **[Porting Guide](./docs/porting.md):** A brief document with basic instructions to add new architectures.

## License & Legal

`infix` is provided under a dual-license model to maximize its usability for all developers.

### Code License

All source code, including header files (`.h`) and implementation files (`.c`),
is dual-licensed under the **Artistic License 2.0** or the **MIT License**. You
may choose to use the code under the terms of either license.

See the [LICENSE-A2](LICENSE-A2) and/or [LICENSE-MIT](LICENSE-MIT) file for the
full text of both licenses.

### Documentation License

All standalone documentation, including this `README.md`, the `cookbook.md`, and
all other markdown files in the `/docs` directory, is licensed under the
**Creative Commons Attribution 4.0 International License (CC BY 4.0)**. This
license encourages you to share and adapt the documentation for any purpose, as
long as you give appropriate credit.

See the [LICENSE-CC](LICENSE-CC) for details.

### Clarification on Embedded Documentation

By default, all content within the source code files (`.h`, `.c`) is licensed as
a whole under the project's code license (Artistic 2.0 / MIT).

However, an additional permission is granted: any explanatory text, including
Doxygen-style documentation blocks, comments, and code examples contained within
the source code, may be separately used, modified, and distributed under the terms
of the **Creative Commons Attribution 4.0 International License (CC BY 4.0)**
*when such text is extracted from and presented separately from the functional
source code.*

This allows for the free use of the project's inline documentation for purposes
such as generating an API reference website, creating tutorials, or adapting the
documentation in other ways while ensuring that the code itself remains under the
A2/MIT license when used as a whole (e.g., when a developer includes `infix.h` in
their project).
