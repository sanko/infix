
# infix: A Modern, JIT-Powered FFI Library for C

**`infix`** is a lightweight, dependency-free Foreign Function Interface (FFI) library for C17. It uses Just-In-Time (JIT) compilation to dynamically generate machine code "trampolines," allowing you to call functions and create callbacks for any C-compatible ABI without writing a single line of assembly.

At its core, `infix` provides two powerful APIs: a low-level Core API for fine-grained control over type definitions, and a high-level Signature API that can parse a human-readable string like `"{i;d*},c*=>i"` into a fully functional FFI call. This makes it an ideal tool for embedding scripting languages, creating plugin systems, or simply simplifying complex C interoperability tasks.


##  Features

`infix` is engineered around three core principles: **Power**, **Security**, and **Simplicity**.

#### Core Capabilities
*   **Forward Calls:** Call any C function pointer dynamically, with full support for complex arguments (structs, unions, arrays) and variadic functions. The library correctly marshals arguments according to the target ABI.
*   **Reverse Calls (Callbacks):** Generate native, C-callable function pointers from custom handlers. The callback mechanism is thread-safe, re-entrant, and fully supports variadic function signatures, making it suitable for high-performance asynchronous systems.
*   **Rich Type System:** Provides comprehensive support for all standard C types, including primitives (`int`, `double`), pointers, structs, unions, and fixed-size arrays.

#### High-Level Abstraction
*   **Convenient Signature API:** Define entire C function signatures—including nested structs, packed layouts, and function pointers—using a simple and expressive string-based language.
*   **Powerful Parser:** The signature parser can be used directly for advanced applications beyond FFI, such as data marshalling, serialization, or dynamic type inspection.

#### Security & Performance
*   **Secure by Design:** `infix` adheres to strict security principles, validated through extensive testing:
    *   **W^X (Write XOR Execute):** Enforces that memory pages are never writable and executable simultaneously.
    *   **Overflow Hardening:** The type system and parser are protected against integer overflows from malformed or malicious inputs.
    *   **Use-After-Free Protection:** Freed trampolines are converted into inaccessible guard pages, ensuring calls to dangling pointers result in a safe, immediate crash.
    *   **Read-Only Contexts:** Callback context data is made read-only after initialization to protect against runtime memory corruption attacks.
*   **Performance Optimized:** A custom arena allocator minimizes the overhead of trampoline generation by replacing thousands of potential `malloc` calls with simple, contiguous pointer bumps.

#### Portability & Integration
*   **Cross-Platform ABI Support:** Correctly handles calling conventions across multiple architectures and operating systems:
    *   **x86-64:** System V (Linux, macOS, BSD) and Windows x64.
    *   **AArch64 (ARM64):** Standard AAPCS64 (Linux, BSD, Android/Termux), including specific variants for Apple and Windows on ARM.
    * Other architectures should be easy to integrate. See [internals.md](docs/internals.md).
*   **Zero Dependencies & Simple Integration:** As a single-header library, integration is trivial. Add `infix.h` to your project's includes and compile the core `.c` files.

##  Quick Start: Calling `printf`

This example demonstrates how to call the standard library's `printf` function, which has a variadic signature, using the Signature API.

```c
#include <infix.h>
#include <stdio.h> // For the real printf

int main() {
    ffi_trampoline_t* trampoline = NULL;
    // The C signature is `int printf(const char* format, ...)`
    // The infix signature uses a semicolon ';' to separate fixed and variadic arguments.
    const char* signature = "c*;i=>i";

    // 1. Create the FFI trampoline from the signature.
    // The '1' indicates there is one fixed argument before the variadic part.
    ffi_status status = ffi_create_forward_trampoline_from_signature(&trampoline, signature);
    if (status != FFI_SUCCESS) {
        fprintf(stderr, "Failed to create trampoline!\n");
        return 1;
    }

    // 2. Get the callable function pointer.
    ffi_cif_func cif_func = (ffi_cif_func)ffi_trampoline_get_code(trampoline);

    // 3. Prepare the arguments.
    const char* my_string = "The answer is %d\n";
    int my_int = 42;
    void* args[] = { &my_string, &my_int };
    int return_value;

    // 4. Call printf via the trampoline.
    cif_func((void*)printf, &return_value, args);

    printf("printf returned: %d\n", return_value); // Will print the number of chars written.
    ffi_trampoline_free(trampoline);
    return 0;
}
```
##  Building the Project

The project uses [**xmake**](https://xmake.io/) as its build system.

### Prerequisites
*   A C17-compatible compiler (GCC, Clang, or MSVC).
*   [xmake](https://xmake.io/#/guide/installation) installed on your system.

### Commands

1.  **Build the static library:**
    ```bash
    xmake
    ```
    This will compile the `libinfix.a` (or `infix.lib`) library into the `build/` directory.

2.  **Run the test suite:**
    ```bash
    xmake test
    ```

3.  **Build the fuzzing harnesses (requires Clang):**
    ```bash
    xmake f -c clang # Configure the project to use the Clang toolchain
    xmake build fuzz_signature fuzz_trampoline # Build specific fuzzer targets
    ```

### Using Perl

The included Perl script can build the library, run tests, and manage other tasks. Until I port everything to xmake, this is what I use to develop `infix`.

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

##  Integrating `infix` Into Your Project

`infix` is designed to be easy to integrate. You only need to link against the static library and include one header.

### Method 1: Using xmake (Recommended)

If your project already uses xmake, add `infix` as a dependency.

```lua
-- your_project/xmake.lua
add_requires("infix", {git = "https://github.com/sanko/infix.git"})

target("my_app")
    set_kind("binary")
    add_files("src/*.c")
    add_packages("infix")
```

### Method 2: Using CMake

You can integrate `infix` into a CMake project using `add_subdirectory`.

1.  Add `infix` as a submodule or copy it into your project (e.g., under `third_party/`).
2.  Add the following to your `CMakeLists.txt`:

```cmake
# your_project/CMakeLists.txt
cmake_minimum_required(VERSION 3.15)
project(MyProject C)

set(CMAKE_C_STANDARD 17)

# Add the infix subdirectory to the build
add_subdirectory(third_party/infix)

add_executable(my_app src/main.c)

# Link your target against infix
target_link_libraries(my_app PRIVATE infix)

# Expose infix's public include directory to your target
target_include_directories(my_app PRIVATE
    $<TARGET_PROPERTY:infix,INTERFACE_INCLUDE_DIRECTORIES>
)
```

### Method 3: Manual Integration

1.  Build the `infix` static library as described above.
2.  In your project's build process, add the following flags:
    *   **Compiler Flags:** `-I/path/to/infix/include`
    *   **Linker Flags:** `-L/path/to/infix/build/your-platform/release -linfix`

##  API Deep Dive & Examples

`infix` offers two distinct APIs for creating trampolines, allowing you to choose between convenience and control.

### The Signature API (High-Level)

This is the simplest and most common way to use `infix`. You describe the entire function signature in a single string, and the library handles all the parsing and type creation internally.

```c
// int add(int a, int b) { return a + b; }
ffi_trampoline_t* trampoline = NULL;
ffi_create_forward_trampoline_from_signature(&trampoline, "i,i=>i");

// ... use the trampoline ...

ffi_trampoline_free(trampoline);
```

The signature language provides a powerful and concise way to describe C types and function signatures.

#### Primitive Types

| Char | C Type                | Notes                             |
| :--- | :-------------------- | :-------------------------------- |
| `v`  | `void`                | Return type only.                 |
| `b`  | `bool`                |                                   |
| `c`  | `char`                | Signedness is platform-dependent. |
| `a`  | `signed char`         |                                   |
| `h`  | `unsigned char`       |                                   |
| `s`  | `short`               |                                   |
| `t`  | `unsigned short`      |                                   |
| `i`  | `int`                 |                                   |
| `j`  | `unsigned int`        |                                   |
| `l`  | `long`                |                                   |
| `m`  | `unsigned long`       |                                   |
| `x`  | `long long`           |                                   |
| `y`  | `unsigned long long`  |                                   |
| `f`  | `float`               |                                   |
| `d`  | `double`              |                                   |
| `e`  | `long double`         |                                   |
| `n`  | `__int128_t`          | GCC/Clang only.                   |
| `o`  | `__uint128_t`         | GCC/Clang only.                   |

#### Constructs

| Construct       | Signature Example                          | C Equivalent                                                   |
| :-------------- | :----------------------------------------- | :------------------------------------------------------------- |
| Pointer         | `i*`                                       | `int*`                                                         |
| Array           | `[10]d`                                    | `double[10]`                                                   |
| Struct          | `{i;d}`                                    | `struct { int f1; double f2; }`                                |
| Union           | `<i;d>`                                    | `union { int f1; double f2; }`                                 |
| Named Fields    | `{count:i; name:c*}`                       | `struct { int count; char* name; }`                            |
| Packed Struct   | `p(5,1){c@0;i@1}`                          | `struct S { char c; int i; } __attribute__((packed));`          |
| Function Pointer| `(i=>j)`                                   | `unsigned int (*)(int)`                                        |

### The Core API (Low-Level)

For programmatic type construction or when type information is only available at runtime, the Core API gives you full control. It requires you to build up each type description manually.

The central concept is the `ffi_type` struct, which holds the size, alignment, and category of any C type.

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

#### **1. Primitive Types**

Primitives are created by referencing static, built-in types.

```c
// Get a pointer to the static ffi_type for a signed 32-bit integer.
ffi_type* int_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32);
```

These return pointers to global instances. **Do not free them.**

#### **2. Aggregate Types (Structs, Unions, Arrays)**

Complex types are built dynamically from their constituent parts.

-   **Structs:** `ffi_type_create_struct()` requires an array of `ffi_struct_member` objects. You must use the `offsetof` macro to provide the correct memory layout.
-   **Unions:** `ffi_type_create_union()` is similar to the struct creator.
-   **Arrays:** `ffi_type_create_array()` takes an element type and a count.

These functions dynamically allocate memory. The returned `ffi_type` **must** be freed with `ffi_type_destroy()`. This will recursively free all nested dynamic types.

#### **Core API Example: Building a Struct**
Here is how to create a trampoline for `Point create_point(Point p1, Point p2)` using the Core API.

```c
typedef struct { double x; double y; } Point;

// 1. Describe the primitive member type (double).
ffi_type* double_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_DOUBLE);

// 2. Describe the members of the Point struct using their offsets.
ffi_struct_member point_members[] = {
    ffi_struct_member_create("x", double_type, offsetof(Point, x)),
    ffi_struct_member_create("y", double_type, offsetof(Point, y))
};

// 3. Create the ffi_type for the Point struct.
ffi_type* point_type = NULL;
ffi_type_create_struct(&point_type, point_members, 2);

// 4. Define the function signature: two Point args, one Point return.
ffi_type* arg_types[] = { point_type, point_type };
ffi_trampoline_t* trampoline = NULL;
generate_forward_trampoline(&trampoline, point_type, arg_types, 2, 2);

// ... use the trampoline ...

ffi_trampoline_free(trampoline);
// 5. Clean up the dynamically created ffi_type for the struct.
ffi_type_destroy(point_type);
```

### Advanced Example: Creating a Callback

Create a C-callable function pointer from a custom handler. This is essential for plugins or asynchronous libraries.

```c
// Our custom handler that will be called by C code.
int my_handler(int x) {
    printf("My callback was called with: %d\n", x);
    return x * 2;
}

// A C function that accepts a function pointer.
void run_callback(int (*fn_ptr)(int)) {
    int result = fn_ptr(21);
    printf("Callback returned %d to the C caller.\n", result);
}

ffi_reverse_trampoline_t* reverse_trampoline = NULL;
const char* signature = "i=>i";

// 1. Create the reverse trampoline.
ffi_create_reverse_trampoline_from_signature(
    &reverse_trampoline,
    signature,
    (void*)my_handler, // Pointer to our handler
    NULL               // Optional user data
);

// 2. Get the native, C-callable function pointer.
int (*native_fn_ptr)(int) = (int (*)(int))reverse_trampoline->exec_code.rx_ptr;

// 3. Pass the function pointer to C code.
run_callback(native_fn_ptr);

ffi_reverse_trampoline_free(reverse_trampoline);
```

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

## Project Structure

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

## Learn More

*   **[Cookbook](./docs/cookbook.md):** Practical, copy-pasteable recipes for common FFI tasks.
*   **[Internals](./docs/internals.md):** A deep dive into the library's architecture for maintainers and contributors.
*   **[Porting Guide](./docs/porting.md):** A brief document with basic instructions to add new architectures.

##  Contributing

Contributions are welcome! Please feel free to open an issue or submit a pull request.

Check [CONTRIBUTING.md](CONTRIBUTING.md) for more!

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
