# infix: A Lightweight FFI Code Generation Library for C

**infix** is a minimal, dependency-free, Just-in-Time (JIT) powered Foreign Function Interface (FFI) library for modern C. It allows you to dynamically create function calls and callbacks at runtime by generating machine code on the fly.

The entire project is written from scratch in C17 and serves as a practical example of how low-level code generation, ABI-specific logic, and memory management work together.

### Features

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
*   **Convenient String-Based API**: Define complex C function signatures, including packed structs and function pointers, using a simple, human-readable string. Use the powerful signature parser directly for tasks like data marshalling, serialization, or dynamic type inspection.

## API Quick Reference

infix provides two API layers: a convenient high-level Signature API and a powerful low-level Core API. The Signature API is recommended for most use cases due to its simplicity and readability. The Core API offers maximum control for dynamically constructing types at runtime.

### The Signature API (Recommended)

This API uses simple strings to define function signatures, making it easy to use and read.

#### Signature Language Reference

The signature string is a powerful mini-language for describing C types, using Itanium ABI characters for primitives.

| Category             | Syntax                                       | Example                                     | Represents                                     |
| :------------------- | :------------------------------------------- | :------------------------------------------ | :--------------------------------------------- |
| **Primitives**       | See table below                              | `i`, `d`, `h`                               | `int`, `double`, `unsigned char`               |
| **Pointer**          | `T*` (postfix)                               | `i*`, `h**`                                 | `int*`, `unsigned char**`                      |
| **Array**            | `[N]T` (prefix)                              | `[10]i`                                     | `int[10]`                                      |
| **Struct**           | `{T1, T2}`                                   | `{i,d}`                                     | `struct { int f1; double f2; }`                |
| **Struct (Named)**   | `{name1:T1}`                                 | `{id:i,val:d}`                              | `struct { int id; double val; }`               |
| **Union**            | `<T1, T2>`                                   | `<i,d>`                                     | `union { int i; double d; }`                   |
| **Union (Named)**    | `<name1:T1>`                                 | `<as_int:i,as_dbl:d>`                       | `union { int as_int; double as_dbl; }`          |
| **Packed Struct**    | `p(size,align){T@off1}`                      | `p(5,1){c@0,i@1}`                           | `_Pragma("pack(1)") struct { char; int; }`      |
| **Function Ptr**     | `(fixed;variadic=>ret)*`                     | `(i=>v)*`                                   | `void (*)(int)`                                |
| **Full Signature**   | `fixed1,fixed2;variadic1=>ret_type`          | `a*,i;d=>i`                                 | `int fn(signed char*, int,)`               |

**Primitive Type Codes (from Itanium ABI):**

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

### The Core API (For Advanced Control)

This API gives you fine-grained control by requiring you to build type descriptions manually. It's more verbose but powerful for programmatically constructing types.

**Core API Type Reference:**

| C Type / Construct       | `ffi_primitive_type_id`          | Core API Function Call                               |
| :----------------------- | :------------------------------- | :--------------------------------------------------- |
| `void`                   | N/A                              | `ffi_type_create_void()`                             |
| Pointer Type             | N/A                              | `ffi_type_create_pointer()`                          |
| `bool`                   | `FFI_PRIMITIVE_TYPE_BOOL`        | `ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_BOOL)` |
| `signed char`            | `FFI_PRIMITIVE_TYPE_SINT8`       | `ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT8)`|
| `unsigned char`          | `FFI_PRIMITIVE_TYPE_UINT8`       | `ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_UINT8)`|
| `short`                  | `FFI_PRIMITIVE_TYPE_SINT16`      | `ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT16)`|
| `unsigned short`         | `FFI_PRIMITIVE_TYPE_UINT16`      | `ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_UINT16)`|
| `int`                    | `FFI_PRIMITIVE_TYPE_SINT32`      | `ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32)`|
| `unsigned int`           | `FFI_PRIMITIVE_TYPE_UINT32`      | `ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_UINT32)`|
| `long long`              | `FFI_PRIMITIVE_TYPE_SINT64`      | `ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT64)`|
| `unsigned long long`     | `FFI_PRIMITIVE_TYPE_UINT64`      | `ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_UINT64)`|
| `__int128_t`             | `FFI_PRIMITIVE_TYPE_SINT128`     | `ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT128)`|
| `__uint128_t`            | `FFI_PRIMITIVE_TYPE_UINT128`     | `ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_UINT128)`|
| `float`                  | `FFI_PRIMITIVE_TYPE_FLOAT`       | `ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_FLOAT)`|
| `double`                 | `FFI_PRIMITIVE_TYPE_DOUBLE`      | `ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_DOUBLE)`|
| `long double`            | `FFI_PRIMITIVE_TYPE_LONG_DOUBLE` | `ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_LONG_DOUBLE)`|
| `struct`                 | N/A                              | `ffi_type_create_struct()`                           |
| `union`                  | N/A                              | `ffi_type_create_union()`                            |
| `array`                  | N/A                              | `ffi_type_create_array()`                            |
| Packed `struct`          | N/A                              | `ffi_type_create_packed_struct()`                    |

## API Examples: Signature vs. Core

The best way to understand the two APIs is to see them side-by-side.

### Example 1: Simple Function Call

**Goal**: Call `int add(int a, int b);`

#### Using the Signature API (Recommended)

```c
#include <infix.h>
#include <stdio.h>

int add_ints(int a, int b) { return a + b; }

int main() {
    ffi_trampoline_t* t = NULL;
    ffi_create_forward_trampoline_from_signature(&t, "i,i=>i");

    int a = 40, b = 2, result = 0;
    void* args[] = { &a, &b };
    ((ffi_cif_func)ffi_trampoline_get_code(t))((void*)add_ints, &result, args);

    printf("Result: %d\n", result);
    ffi_trampoline_free(t);
    return 0;
}
```

#### Using the Core API

```c
#include <infix.h>
#include <stdio.h>

int add_ints(int a, int b) { return a + b; }

int main() {
    ffi_type* ret_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32);
    ffi_type* arg_types[] = {
        ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32),
        ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32)
    };

    ffi_trampoline_t* t = NULL;
    generate_forward_trampoline(&t, ret_type, arg_types, 2, 2);

    int a = 40, b = 2, result = 0;
    void* args[] = { &a, &b };
    ((ffi_cif_func)ffi_trampoline_get_code(t))((void*)add_ints, &result, args);

    printf("Result: %d\n", result);
    ffi_trampoline_free(t);
    return 0;
}
```

### Example 2: Function with Structs and Pointers

**Goal**: Call `Point* create_point(double x, double y);` where `Point` is `struct { double x, y; }`.

#### Using the Signature API (Recommended)

```c
#include <infix.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct { double x; double y; } Point;
Point* create_point(double x, double y) {
    Point* p = malloc(sizeof(Point));
    p->x = x; p->y = y;
    return p;
}

int main() {
    ffi_trampoline_t* t = NULL;
    // Signature: takes two doubles, returns a pointer to a struct of two doubles
    ffi_create_forward_trampoline_from_signature(&t, "d,d=>{d,d}*");

    double x = 1.5, y = 2.5;
    Point* result = NULL;
    void* args[] = { &x, &y };
    ((ffi_cif_func)ffi_trampoline_get_code(t))((void*)create_point, &result, args);

    if (result) {
        printf("Created point at %p with values (%f, %f)\n", result, result->x, result->y);
        free(result);
    }

    ffi_trampoline_free(t);
    return 0;
}
```

#### Using the Core API

```c
#include <infix.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

typedef struct { double x; double y; } Point;
Point* create_point(double x, double y) { /* same as above */ }

int main() {
    // 1. Manually describe the Point struct type.
    ffi_struct_member* members = malloc(sizeof(ffi_struct_member) * 2);
    members[0] = ffi_struct_member_create("x", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_DOUBLE), offsetof(Point, x));
    members[1] = ffi_struct_member_create("y", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_DOUBLE), offsetof(Point, y));
    ffi_type* point_type = NULL;
    ffi_type_create_struct(&point_type, members, 2);

    // 2. Describe the function signature.
    // The return type is a generic pointer. The ABI doesn't need to know what it points to.
    ffi_type* ret_type = ffi_type_create_pointer();
    ffi_type* arg_types[] = {
        ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_DOUBLE),
        ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_DOUBLE)
    };

    // 3. Generate the trampoline.
    ffi_trampoline_t* t = NULL;
    generate_forward_trampoline(&t, ret_type, arg_types, 2, 2);

    // 4. Call and cleanup.
    double x = 1.5, y = 2.5;
    Point* result = NULL;
    void* args[] = { &x, &y };
    ((ffi_cif_func)ffi_trampoline_get_code(t))((void*)create_point, &result, args);

    if (result) { /* print and free */ }

    ffi_trampoline_free(t);
    ffi_type_destroy(point_type); // IMPORTANT: Must free the dynamic struct type.
    return 0;
}
```

### Example 3: Function with Packed Struct and Arrays

**Goal**: Call `uint64_t checksum(const PackedData* data);` where `PackedData` is a complex, packed struct.

```c
#pragma pack(push, 1)
typedef struct {
    uint16_t id;    // offset 0, size 2
    char name[10];  // offset 2, size 10
    uint32_t flags; // offset 12, size 4
} PackedData;       // total size 16, align 1
#pragma pack(pop)

uint64_t checksum(const PackedData* data) { /* ... */ }
```

#### Using the Signature API (Recommended)

```c
#include <infix.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

// PackedData struct definition and checksum function

int main() {
    // 1. Construct the signature string with layout metadata.
    char signature[128];
    snprintf(signature, sizeof(signature), "p(%zu,%zu){t@%zu,[10]c@%zu,j@%zu}*=>y",
             sizeof(PackedData), _Alignof(PackedData),
             offsetof(PackedData, id), offsetof(PackedData, name), offsetof(PackedData, flags));

    // 2. Generate and call.
    ffi_trampoline_t* t = NULL;
    ffi_create_forward_trampoline_from_signature(&t, signature);

    PackedData data = { 101, "test_data", 0xABCD };
    const PackedData* ptr_data = &data;
    uint64_t result = 0;
    ((ffi_cif_func)ffi_trampoline_get_code(t))((void*)checksum, &result, &ptr_data);

    // use result
    ffi_trampoline_free(t);
    return 0;
}
```

#### Using the Core API

```c
#include <infix.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

// PackedData struct definition and checksum function

int main() {
    // 1. Manually build the ffi_type for the char[10] array.
    // Note: Core API requires ownershp transfer; we must not free `char_type` ourselves.
    ffi_type* char_array_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT8);
    ffi_type_create_array(&char_array_type, char_type, 10);

    // 2. Manually describe the packed struct members.
    ffi_struct_member* members = malloc(sizeof(ffi_struct_member) * 3);
    members[0] = ffi_struct_member_create("id", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_UINT16), offsetof(PackedData, id));
    members[1] = ffi_struct_member_create("name", char_array_type, offsetof(PackedData, name));
    members[2] = ffi_struct_member_create("flags", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_UINT32), offsetof(PackedData, flags));

    // 3. Create the packed struct type, providing layout metadata.
    ffi_type* packed_type = NULL;
    ffi_type_create_packed_struct(&packed_type, sizeof(PackedData), _Alignof(PackedData), members, 3);

    // 4. Describe the function signature: uint64_t(PackedData*)
    ffi_type* ret_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_UINT64);
    ffi_type* arg_type = ffi_type_create_pointer();

    // 5. Generate and call.
    ffi_trampoline_t* t = NULL;
    generate_forward_trampoline(&t, ret_type, &arg_type, 1, 1);

    // call is identical to signature example

    ffi_trampoline_free(t);
    ffi_type_destroy(packed_type); // This frees the struct, its members array, and the char array type.
    return 0;
}
```

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

### Building the Project

**Prerequisites:**
*   A C17-compatible compiler like GCC, Clang, or MSVC.
*   [**Perl**](https://github.com/perl/perl5) or [**xmake**](https://xmake.io).

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

#### Using XMake

XMake is a modern, cross-platform build utility that can build the library and run its tests with simple commands.

```bash
# Build the static library (libinfix.a or infix.lib)
# The output will be in the build/ directory.
xmake

# Run the entire test suite
xmake test

# To clean build files
xmake clean

# To switch compilers (e.g., to test with GCC, Clang, and MSVC)
# This only needs to be run once to configure the project.
xmake f -c --toolchain=gcc
xmake f -c --toolchain=clang
xmake f -c --toolchain=msvc
```

### Integrating infix Into Your Project

To use infix in your own application, you need to include the public header and link against the static library.

#### With Perl

To use infix in your own application:

1.  Run `perl build.pl build` to produce the static library (`libinfix.a` or `infix.lib`) in `/build_lib`.
2a. Use the built library in situ or...
2b. Copy the static library and the `include/` directory into your project's source tree.
3.  Include the main header in your code: `#include "infix.h"`
4.  When compiling your application, tell the compiler where to find the header files and how to link the library.

#### With XMake

If your project also uses XMake, integration is trivial. Place the `infix` project directory inside your project (e.g., in a `libs/` folder) and add it to your `xmake.lua`.

**Example Project Structure:**

```
my_project/
├── libs/
│   └── infix/          <-- The infix project directory
│       ├── src/
│       ├── include/
│       └── xmake.lua
├── src/
│   └── main.c
└── xmake.lua
```

**Your `xmake.lua`:**

```lua
add_rules("mode.debug", "mode.release")

target("my_app")
    set_kind("binary")
    add_files("src/main.c")

    -- 1. Tell XMake about the dependency in the subdirectory
    add_deps("infix", {public = false})

    -- 2. Include the subdirectory in the build
    includes("libs/infix")
```

That's it! XMake will automatically build `infix` and link it to `my_app`. Because `infix`'s `xmake.lua` marks its `include` directory as public, you don't even need to add an `add_includedirs` call.

#### Manual Linking (GCC/Clang)

1.  Build the static library (`libinfix.a`).
2.  Copy the library and the `include/` directory to your project.
3.  When compiling, tell the compiler where to find the header files and how to link the library.

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
