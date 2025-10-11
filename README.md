# `infix`: A JIT-Powered FFI Library for C

[![CI/CD](https://github.com/your-repo/infix/actions/workflows/ci.yml/badge.svg)](https://github.com/your-repo/infix/actions/workflows/ci.yml)
[![License: MIT/Artistic-2.0](https://img.shields.io/badge/License-MIT%20%2F%20Artistic--2.0-blue.svg)](https://opensource.org/licenses/MIT)

`infix` is a modern, security-conscious, and dependency-free Foreign Function Interface (FFI) library for C. It simplifies the process of calling native C functions from other environments and creating C-callable function pointers from your own handlers. All with a simple, human-readable string like `({int, *double}, *char) -> int`.

At its core, `infix` is a Just-in-Time (JIT) compiler that generates tiny, highly-optimized machine code "trampolines" at runtime. These trampolines correctly handle the low-level Application Binary Interface (ABI) for the target platform, ensuring seamless and performant interoperability.

## Who is this for?

`infix` is designed for developers who need to bridge the gap between different codebases or language runtimes. You'll find it especially useful if you are:

*   **A Language Binding Author:** `infix` is the ideal engine for allowing a high-level language like Python, Ruby, Perl, or Lua to call C libraries. The introspectable type system simplifies the complex task of data marshalling.
*   **A Plugin System Architect:** Build a stable, ABI-agnostic plugin system. `infix` can provide the boundary layer, allowing you to load and call functions from shared libraries without tight coupling.
*   **A C/C++ Developer:** Dynamically call functions from system libraries (`user32.dll`, `libc.so.6`, etc.) without needing to link against them at compile time, or create complex stateful callbacks for C APIs.
*   **A Security Researcher:** `infix` provides a powerful, fuzz-tested toolkit for analyzing and interacting with native code.

## Key Features

-   **Zero Dependencies & Simple Integration:** `infix` uses a unity build, making integration into any C/C++ project trivial by simply compiling `src/infix.c`.
-   **Simple, Powerful APIs:** Use the high-level **Signature API** to create trampolines from a single string, or drop down to the memory-safe **Manual API** for dynamic, performance-critical use cases.
-   **Advanced Type System:** Full support for primitives, pointers, structs, unions, arrays, enums, `_Complex` numbers, and SIMD vectors.
-   **Named Type Registry:** Define complex types like structs and unions once, and reuse them by name (`@Name`) across all your signatures for unparalleled readability and maintainability.
-   **Stateful Callbacks Made Easy:** The reverse-call API is designed to make stateful callbacks simple and safe, even when the C library you're calling doesn't provide a `user_data` parameter.
-   **Secure by Design:** `infix` is hardened against vulnerabilities and validated through extensive fuzz testing:
    *   **W^X Memory Protection:** JIT-compiled code is never writable and executable at the same time.
    *   **Guard Pages:** Freed trampolines are made inaccessible to prevent **use-after-free** bugs.
    *   **Read-Only Contexts:** Callback context data is made read-only to guard against runtime **memory corruption**.
-   **Cross-Platform and Cross-Architecture:** Designed for portability, with initial support for **x86-64** (System V and Windows x64) and **AArch64** (AAPCS64).
-   **Arena-Based Memory:** Utilizes an efficient arena allocator for all type descriptions, ensuring fast performance and leak-free memory management.
-   **Dynamic Library Tools**: A cross-platform API to load shared libraries (`.so`, `.dll`, `.dylib`), look up symbols, and read/write global variables using the same powerful signature system.

## Getting Started

### Prerequisites

-   A C11-compatible compiler (GCC, Clang, or MSVC).
-   (Optional) A build tool like `cmake`, `xmake`, `make`, etc.

### Building the Library

While you can use the provided build scripts, the simplest way to build `infix` is to compile its single translation unit directly.

```bash
# Build a static library on Linux/macOS
gcc -c -std=c11 -O2 -I/path/to/infix/include src/infix.c -o infix.o
ar rcs libinfix.a infix.o

# Build a static library with MSVC
cl.exe /c /I C:\path\to\infix\include /O2 src\infix.c /Foinfix.obj
lib.exe /OUT:infix.lib infix.obj
```

### Integrating into Your Project

1.  **Include the Header:**
    ```c
    #include <infix/infix.h>
    ```

2.  **Link the Library:** When compiling your application, link against the `libinfix.a` (or `infix.lib`) library.
    ```bash
    gcc my_app.c -I/path/to/infix/include -L/path/to/build/dir -linfix -o my_app
    ```

### Quick Start: A 60-Second Example

Here is a complete, runnable example that calls the standard C library function `puts`.

```c
#include <stdio.h>
#include <infix/infix.h>

int main() {
    // 1. Describe the function signature: int puts(const char*);
    const char* signature = "(*char) -> int32";

    // 2. Create a "bound" trampoline, hardcoding the address of `puts`.
    //    Pass nullptr for the registry as we are not using named types.
    infix_forward_t* trampoline = NULL;
    infix_forward_create(&trampoline, signature, (void*)puts, NULL);

    // 3. Get the callable function pointer.
    infix_bound_cif_func cif = infix_forward_get_code(trampoline);

    // 4. Prepare arguments and call.
    //    The `args` array must contain *pointers* to your argument values.
    const char* my_string = "Hello from infix!";
    void* args[] = { &my_string };
    int return_value;
    cif(&return_value, args); // A non-negative value is returned on success.

    printf("puts returned: %d\n", return_value);

    // 5. Clean up.
    infix_forward_destroy(trampoline);
    return 0;
}
```

## Usage Guide

### Part 1: The Signature Language

The signature language is the most powerful and convenient way to use `infix`.

| Name                 | `infix` Syntax                | Example Signature              | C/C++ Equivalent                 |
| :------------------- | :---------------------------- | :----------------------------- | :------------------------------- |
| **Primitives**       | C type names                  | `"int"`, `"double"`, `"uint64"`| `int`, `double`, `uint64_t`      |
| **Pointers**         | `*<type>`                     | `"*int"`, `"*void"`             | `int*`, `void*`                  |
| **Structs**          | `{<members>}`                 | `"{int, double, *char}"`       | `struct { ... }`                 |
| **Unions**           | `<<members>>`                 | `"<int, float>"`               | `union { ... }`                  |
| **Arrays**           | `[<size>:<type>]`             | `"[10:double]"`                | `double[10]`                     |
| **Function Pointers**| `(<args>)-><ret>`             | `"(int, int)->int"`            | `int (*)(int, int)`              |
| **_Complex**         | `c[<base_type>]`              | `"c[double]"`                  | `_Complex double`                |
| **SIMD Vectors**     | `v[<size>:<type>]`            | `"v[4:float]"`                 | `__m128`, `float32x4_t`         |
| **Enums**            | `e:<int_type>`                | `"e:int"`                      | `enum { ... }`                   |
| **Packed Structs**   | `!{...}` or `!<N>:{...}`       | `"!{char, longlong}"`          | `__attribute__((packed))`        |
| **Variadic Functions**| `(<fixed>;<variadic>)`       | `"(*char; int)->int"`          | `printf(const char*, ...)`      |
| **Named Types**      | `@Name` or `@NS::Name`        | `"@Point"`, `"@UI::User"`      | `typedef struct Point {...}`     |
| **Named Arguments**  | `<name>:<type>`               | `"(count:int, data:*void)"`    | (For reflection only)            |

### Part 2: Common Recipes

#### Forward Call (Calling C from your code)

```c
#include <stdio.h>
#include <infix/infix.h>

int main() {
    // 1. Describe the function signature: int puts(const char*);
    const char* signature = "(*char) -> int32";

    // 2. Create a "bound" trampoline, hardcoding the address of `puts`.
    //    Pass nullptr for the registry as we are not using named types.
    infix_forward_t* trampoline = NULL;
    infix_forward_create(&trampoline, signature, (void*)puts, nullptr);

    // 3. Get the callable function pointer.
    infix_bound_cif_func cif = infix_forward_get_code(trampoline);

    // 4. Prepare arguments and call.
    const char* my_string = "Hello from infix!";
    void* args[] = { &my_string };
    int return_value;
    cif(&return_value, args);

    printf("puts returned: %d\n", return_value);

    // 5. Clean up.
    infix_forward_destroy(trampoline);
    return 0;
}
```

#### Reverse Call (Creating a C callback)

```c
// 1. The custom handler function. Its signature must start with infix_context_t*.
int my_adder_handler(infix_context_t* context, int a, int b) {
    (void)context; // Unused in this simple example
    return a + b;
}

// 2. The native C code that will receive and call our callback.
void run_callback(int (*func_ptr)(int, int)) {
    int result = func_ptr(20, 22);
    printf("Native code received result: %d\n", result); // Prints 42
}

int main() {
    // 3. Create the reverse trampoline (the callback).
    infix_reverse_t* context = NULL;
    const char* signature = "(int32, int32) -> int32";
    infix_reverse_create(&context, signature, (void*)my_adder_handler, NULL, NULL);

    // 4. Get the native C function pointer and pass it to the C code.
    typedef int (*AdderFunc)(int, int);
    run_callback((AdderFunc)infix_reverse_get_code(context));

    // 5. Clean up.
    infix_reverse_destroy(context);
    return 0;
}
```

#### Using the Named Type Registry

```c
// 1. Create a registry.
infix_registry_t* registry = infix_registry_create();

// 2. Define your types as a semicolon-separated string.
const char* my_types =
    "@UserID = uint64;"                          // Create a readable alias.
    "@UI::Point = { x: double, y: double };"     // Define a struct in a namespace.
    "@Node = { value: int, next: *@Node };";     // Define a recursive linked-list node.

// 3. Register the types.
infix_register_types(registry, my_types);

// 4. Use the named types in any signature by passing the registry.
infix_forward_t* trampoline = NULL;
// Assume `get_user_id_from_node` is a C function you want to call.
// infix_forward_create(&trampoline, "(*@Node) -> @UserID", (void*)get_user_id_from_node, registry);

// 5. Clean up.
infix_forward_destroy(trampoline);
infix_registry_destroy(registry);
```

#### Reading Global Variables from a Shared Library

`infix` can read and write to global variables exported from a dynamic library.

**Library Code (`libglobals.c`):**
```c
#if defined(_WIN32)
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

EXPORT int my_global_counter = 42;
```
Compile this into `libglobals.so` or `libglobals.dll`.

**Main Application Code:**
```c
#include <infix/infix.h>
#include <stdio.h>

void main() {
    infix_library_t* lib = infix_library_open("./libglobals.so");
    if (!lib) return;

    int counter_value = 0;
    // 1. Use a signature to describe the variable's type.
    infix_status status = infix_read_global(lib, "my_global_counter", "int32", &counter_value);
    if (status == INFIX_SUCCESS) {
        printf("Initial global value: %d\n", counter_value); // Expected: 42
    }

    // 2. Write a new value.
    int new_value = 100;
    infix_write_global(lib, "my_global_counter", "int32", &new_value);

    // 3. Read it back to confirm.
    infix_read_global(lib, "my_global_counter", "int32", &counter_value);
    printf("Updated global value: %d\n", counter_value); // Expected: 100

    infix_library_close(lib);
}
```

### Part 3: The Manual C API (Advanced)

For dynamic use cases, you can build `infix_type` objects programmatically. All types are allocated from an `infix_arena_t`.

```c
#include <stddef.h> // For offsetof
typedef struct { double x; double y; } Point; // C struct for reference

void build_point_manually() {
    infix_arena_t* arena = infix_arena_create(4096);

    infix_struct_member members;
    members = infix_type_create_member("x", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(Point, x));
    members = infix_type_create_member("y", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(Point, y));

    infix_type* point_type = NULL;
    infix_type_create_struct(arena, &point_type, members, 2);

    // Now `point_type` can be used to create trampolines.

    infix_arena_destroy(arena); // Frees the arena and all types within it.
}
```

### Powerful Introspection for Dynamic Data Marshalling

Beyond just calling functions, `infix` provides a powerful introspection API that allows you to parse a signature string and examine the complete memory layout of a C type at runtime. This is the key feature that makes `infix` an ideal engine for building language bindings, serializers, or any tool that needs to dynamically interact with C data structures.

**Example: Inspecting a C Struct at Runtime**
```c
#include <infix/infix.h>
#include <stdio.h>

// The C struct we want to understand.
typedef struct {
    int32_t user_id;
    double score;
    const char* name;
} UserProfile;

int main() {
    // 1. A signature describing the C struct, with named fields.
    const char* profile_sig = "{id:int32, score:double, name:*char}";

    infix_type* struct_type = NULL;
    infix_arena_t* arena = NULL;

    // 2. Parse the signature to get a detailed, introspectable type object.
    if (infix_type_from_signature(&struct_type, &arena, profile_sig, nullptr) != INFIX_SUCCESS) {
        return 1;
    }

    // 3. Use the introspection API to query the layout.
    printf("Inspecting struct layout for: %s\n", profile_sig);
    printf("Total size: %zu bytes, Alignment: %zu bytes\n",
           infix_type_get_size(struct_type),
           infix_type_get_alignment(struct_type));

    for (size_t i = 0; i < infix_type_get_member_count(struct_type); ++i) {
        const infix_struct_member* member = infix_type_get_member(struct_type, i);
        printf("  - Member '%s': offset=%zu, size=%zu\n",
               member->name,
               member->offset,
               infix_type_get_size(member->type));
    }

    // 4. Clean up the parser's temporary memory.
    infix_arena_destroy(arena);
    return 0;
}
```

**Output on a typical 64-bit system:**
```
Inspecting struct layout for: {id:int32, score:double, name:*char}
Total size: 24 bytes, Alignment: 8 bytes
  - Member 'id': offset=0, size=4
  - Member 'score': offset=8, size=8
  - Member 'name': offset=16, size=8
```

This runtime layout information allows you to, for example, take a Perl hash and correctly pack its key/value pairs into a C `UserProfile` struct in memory, byte by byte.

### Error Handling

Nearly all `infix` API functions return an `infix_status` enum. If an operation fails, you can get detailed, thread-safe error information.

```c
infix_forward_t* trampoline = NULL;
// This will fail if `registry` is NULL or doesn't contain `@MissingType`.
// infix_status status = infix_forward_create(&trampoline, "(@MissingType)->void", my_func, registry);

if (status != INFIX_SUCCESS) {
    infix_error_details_t err = infix_get_last_error();
    fprintf(stderr, "Error creating trampoline!\n");
    fprintf(stderr, "  Category: %d\n", err.category); // e.g., INFIX_CATEGORY_PARSER
    fprintf(stderr, "  Code: %d\n", err.code);       // e.g., INFIX_CODE_UNRESOLVED_NAMED_TYPE
    fprintf(stderr, "  Position: %zu\n", err.position); // Byte offset in signature string
}
```

## API Reference

A brief overview of the complete public API, grouped by functionality.

<details>
<summary><b>Click to expand Full API Reference</b></summary>

### Named Type Registry (`registry_api`)
- `infix_registry_create()`: Creates a new, empty type registry.
- `infix_registry_destroy()`: Frees a registry and all types defined within it.
- `infix_register_types()`: Parses a string of definitions to populate a registry.

### High-Level Signature API (`high_level_api`)
- `infix_forward_create()`: Creates a bound forward trampoline from a signature.
- `infix_forward_create_unbound()`: Creates an unbound forward trampoline from a signature.
- `infix_reverse_create()`: Creates a reverse trampoline (callback) from a signature.
- `infix_signature_parse()`: Parses a full function signature into its `infix_type` components.
- `infix_type_from_signature()`: Parses a string representing a single data type.

### Dynamic Library & Globals API (`exports_api`)
- `infix_library_open()`: Opens a dynamic library (`.so`, `.dll`).
- `infix_library_close()`: Closes a dynamic library handle.
- `infix_library_get_symbol()`: Retrieves a function or variable address from a library.
- `infix_read_global()`: Reads a global variable from a library using a signature.
- `infix_write_global()`: Writes to a global variable in a library using a signature.

### Manual API (`manual_api`)
- `infix_forward_create_manual()`: Creates a bound forward trampoline from `infix_type` objects.
- `infix_forward_create_unbound_manual()`: Creates an unbound forward trampoline from `infix_type` objects.
- `infix_reverse_create_manual()`: Creates a reverse trampoline from `infix_type` objects.
- `infix_forward_destroy()`: Frees a forward trampoline.
- `infix_reverse_destroy()`: Frees a reverse trampoline.

### Type System (`type_system`)
- `infix_type_create_primitive()`: Gets a static descriptor for a primitive C type.
- `infix_type_create_pointer()`: Gets a static descriptor for `void*`.
- `infix_type_create_pointer_to()`: Creates a pointer type with a specific pointee type.
- `infix_type_create_void()`: Gets the static descriptor for the `void` type.
- `infix_type_create_struct()`: Creates a struct type from an array of members.
- `infix_type_create_packed_struct()`: Creates a struct with non-standard packing.
- `infix_type_create_union()`: Creates a union type from an array of members.
- `infix_type_create_array()`: Creates a fixed-size array type.
- `infix_type_create_enum()`: Creates an enum type with an underlying integer type.
- `infix_type_create_complex()`: Creates a `_Complex` number type.
- `infix_type_create_vector()`: Creates a SIMD vector type.
- `infix_type_create_named_reference()`: (Internal) Creates a placeholder for a named type.
- `infix_type_create_member()`: A factory function for `infix_struct_member`.

### Memory Management (`memory_management`)
- `infix_arena_create()`: Creates a new memory arena.
- `infix_arena_destroy()`: Frees an arena and all memory allocated from it.
- `infix_arena_alloc()`: Allocates aligned memory from an arena.
- `infix_arena_calloc()`: Allocates zero-initialized memory from an arena.

### Introspection API (`introspection_api`)
- `infix_forward_get_code()`, `infix_forward_get_unbound_code()`
- `infix_reverse_get_code()`, `infix_reverse_get_user_data()`
- `infix_forward_get_num_args()`, `infix_reverse_get_num_args()`
- `infix_forward_get_return_type()`, `infix_reverse_get_return_type()`
- `infix_forward_get_arg_type()`, `infix_reverse_get_arg_type()`
- `infix_type_get_category()`, `infix_type_get_size()`, `infix_type_get_alignment()`
- `infix_type_get_member_count()`, `infix_type_get_member()`
- `infix_type_get_arg_name()`, `infix_type_get_arg_type()`
- `infix_type_print()`: Serializes an `infix_type` graph to a string.
- `infix_function_print()`: Serializes a full function signature to a string.

### Error Handling API (`error_api`)
- `infix_get_last_error()`: Retrieves detailed information about the last error on the current thread.

</details>

## Supported Platforms

`infix` is rigorously tested on a wide array of operating systems, compilers, and architectures with every commit.

<details>

<summary><strong>Click to view the full CI test matrix</strong></summary>

| OS | Architecture | Compilers | Status |
| :--- | :--- | :--- | :--- |
| Ubuntu (latest) | x86-64 | GCC, Clang | ✅ |
| Ubuntu (latest) | AArch64 | GCC, Clang | ✅ |
| Windows (latest)| x86-64 | MSVC, Clang, GCC (MinGW) | ✅ |
| Windows (latest)| AArch64 | MSVC, Clang | ✅ |
| macOS (latest) | AArch64 | Clang, GCC | ✅ |
| macOS (latest) | x86-64 (cross-compiled) | Clang, GCC | ✅ |
| FreeBSD (latest)| x86-64 | Clang, GCC | ✅ |
| FreeBSD (latest)| AArch64 | Clang, GCC | ✅ |
| OpenBSD (latest)| x86-64 | Clang, GCC | ✅ |
| OpenBSD (latest)| AArch64 | Clang, GCC | ✅ |
| NetBSD (latest) | x86-64 | GCC | ✅ |
| NetBSD (latest) | AArch64 | GCC | ✅ |
| DragonflyBSD (latest)| x86-64 | GCC | ✅ |
| Solaris (11.4) | x86-64 | GCC | ✅ |
| OmniOS (stable)| x86-64 | GCC | ✅ |

</details>

## Building and Integrating

Full build instructions for `xmake`, `cmake`, GNU `make`, and other systems are available in **[INSTALL.md](INSTALL.md)**.

Because `infix` uses a unity build, integration into an existing project is simple: add `src/infix.c` to your list of source files and add the `include/` directory to your include paths.

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue for any bugs, feature requests, or documentation improvements.

## Learn More

*   **[Cookbook](docs/cookbook.md):** Practical, copy-pasteable recipes for common FFI tasks.
*   **[Signature Reference](docs/signatures.md):** The complete guide to the signature mini-language.
*   **[Internals](docs/internals.md):** A deep dive into the library's architecture, JIT engine, and security features.
*   **[Porting Guide](docs/porting.md):** Instructions for adding support for new architectures.
*   **[INSTALL.md](INSTALL.md):** Detailed build and integration instructions.

## License & Legal

`infix` is provided under multiple licenses to maximize its usability for all.

### Code License

Source code, including header files (`.h`) and implementation files (`.c`), is dual-licensed under the **Artistic License 2.0** or the **MIT License**. You may choose to use the code under the terms of either license.

See the [LICENSE-A2](LICENSE-A2) and/or [LICENSE-MIT](LICENSE-MIT) for the full text of both licenses.

### Documentation License

All standalone documentation (`.md`), explanatory text, Doxygen-style documentation blocks, comments, and code examples contained within this repository may be used, modified, and distributed under the terms of the **Creative Commons Attribution 4.0 International License (CC BY 4.0)**. We encourage you to share and adapt the documentation for any purpose (generating an API reference website, creating tutorials, etc.), as long as you give appropriate credit.

See the [LICENSE-CC](LICENSE-CC) for details.
