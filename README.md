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
*   **Exposed Signature Parser**: Use the powerful signature parser directly for tasks like data marshalling, serialization, or dynamic type inspection.

## API Quick Reference

infix provides two API layers: a convenient high-level Signature API and a powerful low-level Core API.

#### 1. The Signature API

This API uses simple strings to define function signatures, making it easy to use and read.

**For Creating Trampolines:**

```c
#include <infix.h>

// Generate a forward trampoline for `int add(int, int)`
ffi_trampoline_t* t;
ffi_create_forward_trampoline_from_signature(&t, "ii => i");

// Generate a reverse trampoline (callback) for `void handler(char*)`
ffi_reverse_trampoline_t* rt;
ffi_create_reverse_trampoline_from_signature(&rt, "c* => v", my_handler, NULL);
```

**For Parsing and Type Introspection (Advanced):**

Beyond creating trampolines, the signature API now allows you to parse signature strings directly into `ffi_type` objects. This is a powerful feature for building data marshalling systems or other advanced tooling.

```c
#include <infix.h>

// Parse a single struct type signature with named members.
ffi_type* my_struct_type = NULL;
arena_t* arena = NULL; // The parser allocates an arena for the types.
const char* sig = "{i'user_id';d'score'}";

ffi_status status = ffi_type_from_signature(&my_struct_type, &arena, sig);

if (status == FFI_SUCCESS) {
    // You can now inspect member names, types, and offsets.
    printf("Struct member 0: %s\n", my_struct_type->meta.aggregate_info.members.name);

    // IMPORTANT: The caller owns the arena and must destroy it.
    arena_destroy(arena);
}
```

See the **[Cookbook](./docs/cookbook.md)** for a detailed recipe on this.

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
| `T*`                                       | `T*` (e.g., `i*` is `int*`)                      |
| `T**`                                      | `T**` (e.g., `c**` is `char**`)                  |
| `T[N]`                                     | `T[N]` (e.g., `f[16]` is `float[16]`)            |
| `{type1'name1';type2}`                     | `struct { T1 name1; T2 member2; }` (names are optional) |
| `<type1'name1';type2>`                     | `union { T1 name1; T2 member2; }` (names are optional)  |
| `p(size,align){type1:off1;...}`            | A packed struct with explicit layout             |
| `(args...=>ret)`                           | A function pointer, e.g., `(i=>v)` for `void (*)(int)`  |

### Delimiters

| Delimiter | Purpose                                                     |
| :-------- | :---------------------------------------------------------- |
| `=>`      | **Required.** Separates arguments from the return type.     |
| `.`       | **Optional.** Separates fixed arguments from variadic ones. |
| `;`       | **Required.** Separates members inside `{...}` and `<...>` lists. |
| `:`       | **Required.** Separates type from offset in packed structs. |
| `'`       | **Optional.** Encloses member names inside `{...}` and `<...>` lists. |

### Examples

| Signature String                 | Corresponding C Function Signature                                 |
| -------------------------------- | ------------------------------------------------------------------ |
| `ii => i`                        | `int function(int, int);`                                          |
| `c* => v`                        | `void function(char*);` (Also used for `void*`)                    |
| `(i=>v) => v`                    | `void function(void (*callback)(int));`                            |
| `{i;f}c* => v`                   | `void function(struct { int a; float b; }, char*);`                |
| `{i'id';d'score'}c* => v`        | `void function(struct { int id; double score; }, char*);`          |
| `c*.if => i`                     | `int function(const char*, int, float, ...);`                      |
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
