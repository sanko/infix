# infix: JIT-Powered FFI

**`infix`** is a lightweight, dependency-free Foreign Function Interface (FFI) library for C17. It uses Just-In-Time (JIT) compilation to dynamically generate incredibly fast machine code "trampolines," allowing you to call functions and create callbacks for any C-compatible ABI without writing a single line of assembly.

At its core, `infix` provides two powerful APIs: a low-level Manual API for fine-grained control, and a high-level Signature API that can parse a human-readable string like "`{i,d*},c*=>i`" into a fully functional FFI call. This makes it an ideal tool for embedding scripting languages, creating plugin systems, or simplifying complex C interoperability tasks.

## Quick Start: Hello, World

Here is a complete example of calling the standard C library function `puts` to print a message.

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

## Features

-  **Forward Calls:** Call any C function pointer dynamically, with full support for complex arguments (structs, unions, arrays) and variadic functions. The library correctly marshals arguments according to the target ABI.
-  **Reverse Calls (Callbacks):** Generate native, C-callable function pointers from custom handlers. The callback mechanism is thread-safe, re-entrant, and fully supports variadic function signatures, making it suitable for high-performance asynchronous systems.
-  **Rich Type System:** Comprehensive support for all standard C types, including primitives (`int`, `double`), pointers, structs, unions, and fixed-size arrays.
- **High-Level Abstraction**
  -  **Convenient Signature API:** Define entire C function signatures—including nested structs, packed layouts, and function pointers—using a simple and expressive string-based language.
  -  **Powerful Introspection:** The signature parser can be used directly for advanced applications beyond FFI, such as data marshalling, serialization, or dynamic type inspection.
-  **Secure by Design:**  infix adheres to strict security principles, validated through extensive fuzzing:
    -  **W^X (Write XOR Execute):** Enforces that memory pages are never writable and executable simultaneously.
      -  **Overflow Hardening:** The type system and parser are protected against integer overflows from malformed or malicious inputs.
      -  **Use-After-Free Protection:** Freed trampolines are converted into inaccessible guard pages, ensuring calls to dangling pointers result in a safe, immediate crash.
      - **Read-Only Contexts**: Callback context data is made read-only after initialization to protect against runtime memory corruption attacks.
  -   **Performance Optimized:** A custom arena allocator minimizes the overhead of trampoline generation by replacing thousands of potential malloc calls with simple, contiguous pointer bumps.
-   **Customizable Memory Management:** Allows users to override `malloc`, `free`, etc., to integrate with custom memory allocators.
-  **Portability & Integration**

[](https://github.com/sanko/infix/tree/dev#portability--integration)

-   **Cross-Platform ABI Support:**  Correctly handles calling conventions across multiple architectures and operating systems:
    -   **x86-64:**  System V (Linux, macOS, BSD) and Windows x64.
    -   **AArch64 (ARM64):**  Standard AAPCS64 (Linux, BSD, Android/Termux), including specific variants for Apple and Windows on ARM.
    -   Other architectures should be easy to integrate. See  [internals.md](https://github.com/sanko/infix/blob/dev/docs/internals.md).
   -  **Zero Dependencies & Simple Integration:**  As a single-header library, integration is trivial. Add  `infix.h`  to your project's includes and compile the core  `.c`  files.
    -
## Platform Compatibility

| Operating System | Architecture | ABI | Status |
| :--- | :--- | :--- | :--- |
| Windows | x86-64 | Windows x64 | Supported |
| Linux | x86-64 | System V AMD64 | Supported |
| macOS | x86-64 | System V AMD64 | Supported |
| Linux | AArch64 | AAPCS64 | Supported |
| macOS | AArch64 (Apple Silicon) | AAPCS64 (Apple Variant) | Supported |

## Building the Project

The project uses **XMake** for its primary build system. A separate Perl script is provided for advanced tasks like building the fuzzing harnesses.

### Prerequisites

-   [XMake](https://xmake.io/)
-   A C17-compatible compiler (GCC, Clang, or MSVC).
-   Perl (for running the fuzzing build script).

### Common Build Commands

-   **Configure and Build the Library:**
    ```bash
    xmake
    ```

-   **Run All Tests:**
    ```bash
    xmake test
    ```

-   **Build Fuzzing Harnesses (Clang/AFL++):**
    The fuzzing harnesses must be built using the provided Perl script, which correctly configures the compiler flags for sanitizers and fuzzer integration.

    ```bash
	# Build the static library (libinfix.a or infix.lib)
	perl build.pl build

	# Specify a compiler (msvc, gcc, clang):
	perl build.pl build --compiler=clang

	# Run all standard tests
	perl build.pl test

	# Run the memory stress test under Valgrind (on Linux)
	perl build.pl memtest

	# Build a fuzzer (requires Clang for libFuzzer or AFL-GCC for AFL++)
	perl build.pl fuzz:signature --cc=clang
	```

## Integrating `infix` into Your Project

You can integrate `infix` into your own projects using several methods, depending on your build system.

### Using XMake (Recommended)

If your project already uses XMake, this is the simplest method.

In your project's `xmake.lua`, use `add_subdirs()` to include the `infix` build script and `add_deps()` to link your target against it.

```lua
    -- Your project's xmake.lua
    set_project("my_awesome_app")
    set_version("1.0.0")
    set_languages("c17")

    -- 1. Tell XMake where to find the infix project
    add_requires("infix", {git = "https://github.com/sankorobinson/infix.git"})

    -- Define your application's target
    target("my_awesome_app")
        set_kind("binary")
        add_files("src/*.c")

        -- 2. Link against the "infix" static library target
        add_deps("infix")
```

Now, you can simply include the header (`#include <infix.h>`) in your source files and build your project with `xmake`.

### Manual Integration (CMake, Make, etc.)

If you use a different build system like Make or want to compile manually, you can build `infix` as a static library first and then link it.

#### Step 1: Build the Static Library

You can use either XMake or the provided Perl script to build the library.

-   **Using XMake:**
    ```bash
    # This will build the static library
    xmake
    ```
    The library will be located in the `build/` directory, typically at a path like `build/windows/x64/release/infix.lib` (Windows) or `build/linux/x86_64/release/libinfix.a` (Linux).

-   **Using the Perl Script:**

    ```bash
    perl build.pl build
    ```
    The library will be created in the `build_lib/` directory as `infix.lib` (Windows) or `libinfix.a` (Linux/macOS).

#### Step 2: Link the Library in Your Project

You now need to tell your compiler where to find the `infix` header files and the static library you just built.

-   **For GCC/Clang:**
    Use the `-I` flag for the include directory, `-L` for the library directory, and `-l` to link the library.

    ```bash
    # Assuming infix was built with the Perl script
    gcc my_app.c \
        -I/path/to/infix/include \
        -L/path/to/infix/build_lib \
        -linfix \
        -o my_app
    ```

-   **For MSVC:**
    In your IDE (like Visual Studio), add the `infix/include` directory to your project's "Additional Include Directories" and the directory containing `infix.lib` to your "Additional Library Directories". Then, add `infix.lib` to your "Additional Dependencies".

### Using CMake

While `infix` does not ship with a `CMakeLists.txt`, you can easily integrate the pre-built static library into your CMake project.

1.  **Add `infix` as a Git Submodule** (same as above).

2.  **Build the `infix` Static Library** using one of the manual methods described above.

3.  **Update Your `CMakeLists.txt`**

    Use `add_library` with the `IMPORTED` option to create a CMake target for `infix`. This makes it easy to manage the dependency.

    ```cmake
    # Your project's CMakeLists.txt
    cmake_minimum_required(VERSION 3.15)
    project(my_awesome_app C)

    # Path to the infix submodule
    set(INFIX_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libs/infix)

    # 1. Create an IMPORTED target for the pre-built infix library
    add_library(infix STATIC IMPORTED)

    # 2. Tell CMake where to find the library file and header files
    set_target_properties(infix PROPERTIES
        IMPORTED_LOCATION "${INFIX_DIR}/build_lib/libinfix.a" # Or .lib on Windows
        INTERFACE_INCLUDE_DIRECTORIES "${INFIX_DIR}/include"
    )

    # 3. Define your application executable
    add_executable(my_awesome_app src/main.c)

    # 4. Link your app against the infix target. CMake handles the rest.
    target_link_libraries(my_awesome_app PRIVATE infix)
    ```
## API Overview

`infix` provides two distinct APIs for creating trampolines: a high-level **Signature API** and a low
-level **Manual API**.

### Core Concepts

-   **`ffi_type`**: The central data structure that describes any C type.
-   **Trampoline**: A small piece of machine code JIT-compiled by `infix` that bridges calling conventions.
-   **`ffi_cif_func`**: A generic function pointer for invoking a forward trampoline: `void (*ffi_cif_func)(void* target_function, void* return_value, void** args);`

### Arena Memory Allocator

For performance-critical applications and internal parsing, `infix` exposes an efficient arena allocator. An arena pre-allocates a single large block of memory and serves subsequent allocation requests by simply "bumping" a pointer.

-   **Speed:** Replaces thousands of `malloc` calls with cheap pointer increments.
-   **Simplicity:** Frees all memory allocated within the arena with a single `arena_destroy()` call, eliminating complex cleanup logic.

The high-level Signature API uses an arena internally to manage all `ffi_type` objects created during parsing.

### Introspection and Type Parsing

`infix` provides powerful functions for parsing signature strings without creating a trampoline. This is useful for dynamic type inspection, data marshalling, or building C structs in allocated memory at runtime.

-   **`ffi_signature_parse()`**: Parses a full function signature string into its constituent parts: a return `ffi_type`, an array of argument `ffi_type*`, and argument counts.
-   **`ffi_type_from_signature()`**: Parses a string representing a single data type (e.g., a struct or array).

Both functions allocate the resulting `ffi_type` object graph from a new arena and return a pointer to it, giving the caller full ownership. You can then traverse the `ffi_type` structure to learn about its size, alignment, and members.

---

## The Signature API (Recommended)

This is the simplest and most common way to use infix. You describe the entire function signature in a single string, and the library handles all the parsing and type creation internally.

```c
// int add(int a, int b) { return a + b; }
ffi_trampoline_t* trampoline = NULL;
ffi_create_forward_trampoline_from_signature(&trampoline, "i,i=>i");

// ... use the trampoline ...

ffi_trampoline_free(trampoline);
```
The signature language provides a powerful and concise way to describe C types and function signatures. The format is `arg1_type, arg2_type ... => return_type`.

#### Primitive Type Specifiers

| Specifier | C Type | Description |
| :--- | :--- | :--- |
| `v` | `void` | Used exclusively for return types. |
| `b` | `bool` | |
| `c` | `char` | Correctly resolves to `signed` or `unsigned` depending on the platform. |
| `a` | `int8_t` / `signed char` | |
| `h` | `uint8_t` / `unsigned char` | |
| `s` | `int16_t` / `short` | |
| `t` | `uint16_t` / `unsigned short` | |
| `i` | `int32_t` / `int` | |
| `j` | `uint32_t` / `unsigned int` | |
| `l` | `long` | |
| `m` | `unsigned long` | |
| `x` | `int64_t` / `long long` | |
| `y` | `uint64_t` / `unsigned long long` | |
| `f` | `float` | |
| `d` | `double` | |
| `e` | `long double`| |
| `n` | `__int128_t`| GCC/Clang only. |
| `o` | `__uint128_t`| GCC/Clang only. |

#### Structural and Delimiter Specifiers

-   `*`: Postfix modifier for a **pointer** (e.g., `i*` is `int*`).
-   `{...}`: Defines a **struct** (e.g., `{i,d}`).
-   `<...>`: Defines a **union** (e.g., `<i,d>`).
-   `[...]`: Defines an **array** (e.g., `[10]i` is `int[10]`).
-   `p(...)`: Defines a **packed struct** with explicit layout: `p(size,align){type@offset;...}`.
-   `(...)`: Defines a **function pointer** type.
-   `,`: Separates regular arguments.
-   `;`: Separates fixed arguments from variadic arguments.
-   `=>`: Separates arguments from the return type.
-   `@`: Separates a packed struct member from its byte offset.
-   `:`: Separates a member name from its type.

### Signature Examples

| C Function Signature | Signature String | Explanation |
| :--- | :--- | :--- |
| `int max(int a, int b);` | `i,i=>i` | Two `int` args, `int` return. |
| `void print_point(const Point* p);` <br> `struct Point { int x; double y; }` | `{i,d}*=>v` | A pointer `*` to a struct `{i,d}` as an argument, `void` return. |
| `int printf(const char* format, ...);` | `c*;=>i` | A `char*` (`c*`), then variadic args (indicated by `;`), `int` return. |
| `uint64_t checksum(const PackedData* data);` <br> `struct __attribute__((packed)) { char c; int i; }` | `p(5,1){c@0;i@1}*=>y` | A pointer `*` to a packed struct `p(5,1){...}` as an argument, `uint64_t` (`y`) return. |
| `void register_callback(void (*cb)(int));` | `(i=>v)*=>v` | The argument is a pointer `*` to a function `(i=>v)`. The main function returns `void`. |
| `User** find_users(int* count);` <br> `struct User { const char* name; int id; }` | `i*=>{c*,i}**` | An `int*` argument. Returns a pointer-to-a-pointer `**` to a struct `{c*,i}`. |

---

## The Manual API (Advanced)

This API gives you fine-grained control by requiring you to manually build the `ffi_type` object graph for a function signature.

### Memory Ownership Model

-   **Caller Owns**: You are responsible for freeing any `ffi_type` created with `ffi_type_create_struct`, `_union`, or `_array` by calling `ffi_type_destroy`. You are also responsible for freeing any trampoline handle (`ffi_trampoline_t` or `ffi_reverse_trampoline_t`) with its corresponding `_free` function.
-   **Library Owns**: The library takes ownership of the `members` array passed to `ffi_type_create_struct` *only on success*. On failure, you must free it.
-   **Static Types**: Types created with `ffi_type_create_primitive`, `_pointer`, or `_void` are static singletons and **must not** be freed. `ffi_type_destroy` will safely ignore them.

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

### Manual API Function List

These functions provide direct access to the `infix` core.

#### Type System API
-   `ffi_type_create_primitive()`: Gets a static descriptor for a C primitive.
-   `ffi_type_create_pointer()`: Gets the static descriptor for a pointer.
-   `ffi_type_create_void()`: Gets the static descriptor for `void`.
-   `ffi_type_create_struct()`: Creates a new struct type from an array of members.
-   `ffi_type_create_packed_struct()`: Creates a struct type with a specific, non-standard memory layout.
-   `ffi_type_create_union()`: Creates a new union type.
-   `ffi_type_create_array()`: Creates a new fixed-size array type.
-   `ffi_type_destroy()`: Frees a dynamically-created `ffi_type` and its members.

#### Trampoline Generation API
-   `generate_forward_trampoline()`: JIT-compiles a forward call trampoline from manual `ffi_type`s.
-   `generate_reverse_trampoline()`: JIT-compiles a reverse call (callback) trampoline.

#### Trampoline Management API
-   `ffi_trampoline_get_code()`: Retrieves the executable code pointer from a forward trampoline.
-   `ffi_trampoline_free()`: Frees a forward trampoline.
-   `ffi_reverse_trampoline_get_code()`: Retrieves the executable code pointer from a reverse trampoline.
-   `ffi_reverse_trampoline_get_user_data()`: Retrieves the user data associated with a callback.
-   `ffi_reverse_trampoline_free()`: Frees a reverse trampoline.

---

## Advanced Topics

### Customizable Memory Management

You can redirect all of `infix`'s internal memory allocations by defining the following macros before including `infix.h`:   `infix_malloc`, `infix_calloc`, `infix_realloc`, `infix_free`, `infix_memcpy`, `infix_memset`

**Why?**
-   **Integration:** To integrate `infix` into a larger application or game engine that has its own global memory manager.
-   **Performance:** To use a custom, high-performance allocator (like a memory pool) for FFI-related objects.
-   **Debugging:** To route allocations through a custom wrapper for leak detection or memory tracking.

```c
// Example: Using a custom allocator
#define infix_malloc my_custom_malloc
#define infix_free my_custom_free
#include "infix.h"
```

### Error Handling

Most `infix` API functions return an `ffi_status` enum. A successful operation will always return `FFI_SUCCESS`. Any other value indicates an error.

```c
ffi_trampoline_t* trampoline = NULL;
ffi_status status = ffi_create_forward_trampoline_from_signature(&trampoline, "invalid signature");

if (status != FFI_SUCCESS) {
    // Handle the error. For example:
    if (status == FFI_ERROR_INVALID_ARGUMENT) {
        fprintf(stderr, "Error: The signature string was malformed.\n");
    } else if (status == FFI_ERROR_ALLOCATION_FAILED) {
        fprintf(stderr, "Error: A memory allocation failed.\n");
    }
    // ...
}
```

### Platform Detection Macros

`infix.h` automatically detects the build environment and defines a set of preprocessor macros that you can use for platform-specific code.

-   **`FFI_OS_*`**: (`FFI_OS_WINDOWS`, `FFI_OS_MACOS`, `FFI_OS_LINUX`, etc.) for the operating system.
-   **`FFI_ARCH_*`**: (`FFI_ARCH_X64`, `FFI_ARCH_AARCH64`) for the CPU architecture.
-   **`FFI_ABI_*`**: (`FFI_ABI_WINDOWS_X64`, `FFI_ABI_SYSV_X64`, `FFI_ABI_AAPCS64`) for the Application Binary Interface.
-   **`FFI_COMPILER_*`**: (`FFI_COMPILER_MSVC`, `FFI_COMPILER_CLANG`, `FFI_COMPILER_GCC`) for the compiler.
-   **`FFI_ENV_*`**: (`FFI_ENV_POSIX`, `FFI_ENV_MINGW`) for specific build environments.


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
