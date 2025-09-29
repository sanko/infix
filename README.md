# `infix`: A JIT-Powered FFI Library for C

`infix` is a modern FFI library for C that lets you call any C function—or create C callbacks—by describing them in a simple, human-readable string like `({int, *double}, *char) -> int`.

At its core, `infix` is a Just-in-Time (JIT) compiler that generates tiny, highly-optimized machine code wrappers. These "trampolines" handle all the low-level details of the target platform's calling convention (ABI) behind a clean, uniform API. This makes `infix` a powerful tool for embedding scripting languages, building plugin systems, and simplifying complex C interoperability.

## Quick Start: Calling a Shared Library

This example demonstrates a core FFI use case: dynamically loading a shared library (`.dll` or `.so`), retrieving a function pointer from it, and calling that function.

```c
#include <infix/infix.h>
#include <stdio.h>

// Platform-specific headers for dynamic library loading
#if defined(_WIN32)
#include <windows.h>
#else
#include <dlfcn.h>
#endif

// Assume say_hello(const char*) is in a shared library
typedef void (*say_hello_func)(const char*);

int main() {
    // 1. Dynamically load the shared library and get the function pointer.
#if defined(_WIN32)
    HMODULE lib_handle = LoadLibraryA("greeting.dll");
    void* say_hello_ptr = (void*)GetProcAddress(lib_handle, "say_hello");
#else
    void* lib_handle = dlopen("./libgreeting.so", RTLD_LAZY);
    void* say_hello_ptr = dlsym(lib_handle, "say_hello");
#endif
    if (!lib_handle || !say_hello_ptr) { return 1; }

    // 2. Create an infix trampoline for the function's signature: void(const char*)
    infix_forward_t* trampoline = NULL;
    infix_forward_create(&trampoline, "(*char) -> void");

    // 3. Prepare arguments and call the function via the trampoline.
    infix_cif_func cif = (infix_cif_func)infix_forward_get_code(trampoline);
    const char* name = "World";
    void* args[] = { &name };
    cif(say_hello_ptr, NULL, args);

    // 4. Clean up.
    infix_forward_destroy(trampoline);
#if defined(_WIN32)
    FreeLibrary(lib_handle);
#else
    dlclose(lib_handle);
#endif
    return 0;
}
```

## Features

-   **Forward Calls:** Call any C function pointer dynamically, with full support for complex arguments and variadic functions.
-   **Reverse Calls (Callbacks):** Generate native, C-callable function pointers from custom handlers. The callback mechanism is thread-safe, re-entrant, and **passes a context pointer as the first argument to your handler**, enabling powerful stateful callbacks.
-   **Expressive Signature API:** Define entire C function signatures—including nested structs and packed layouts—using a simple string-based language.
-   **Powerful Introspection:** Parse signature strings to get detailed type information at runtime—**including what pointers point to and member names**—ideal for data marshalling, code generation, or building language bindings.
-   **Secure by Design:** `infix` adheres to strict security principles, validated through extensive fuzzing:
    -   **W^X Memory Protection:** JIT-compiled code is never writable and executable at the same time.
    -   **Guard Pages:** Freed trampolines are made inaccessible to prevent use-after-free bugs.
    -   **Read-Only Contexts:** Callback context data is made read-only after initialization to guard against runtime memory corruption.
-   **Cross-Platform ABI Support:** Correctly handles calling conventions for **x86-64** (System V, Windows) and **AArch64** (Standard AAPCS64, Apple, and Windows variants).
-   **Zero Dependencies & Simple Integration:** `infix` uses a unity build, making integration with any build system straightforward.

## Building and Integrating

Full build and integration instructions are available in **[INSTALL.md](INSTALL.md)**.

### Quick Build with xmake (Recommended)

```bash
# Build the static library
xmake

# Run all tests
xmake test

# Build and run a specific example
xmake run 01_simple_call
```

### Other Build Systems

`infix` also supports CMake, GNU Make, and NMake. See `INSTALL.md` for details.

## API Overview

`infix` provides two distinct APIs for creating trampolines: a high-level **Signature API** and a low-level **Manual API**.

### The Signature API (Recommended)

This API generates trampolines from a simple string: `(arg1, arg2, ...) -> ret_type`. It's the easiest and safest way to use the library.

> **For a complete guide to the signature language, see the [Signature Language Reference](docs/signatures.md).**

**Key Functions:**
-   `infix_forward_create(tramp, "(int32, int32) -> int32")`: Creates a forward trampoline from a signature string.
-   `infix_reverse_create(ctx, "(int32) -> void", handler, data)`: Creates a callback from a signature string and a C handler.
-   `infix_type_from_signature(type, arena, "{int32, double}")`: Parses a single data type signature for introspection.
-   `infix_signature_parse(...)`: Parses a full function signature for advanced use cases.

### The Manual API (Advanced)

This API gives you fine-grained control by requiring you to build the `infix_type` object graph manually. It is **exclusively arena-based** to ensure memory safety.

**Key Functions:**
-   `infix_arena_create(size)`: Creates a memory arena for fast, temporary allocations.
-   `infix_type_create_primitive(INFIX_PRIMITIVE_SINT32)`: Gets a static descriptor for a C primitive.
-   `infix_type_create_struct(arena, &type, members, num)`: Builds a struct type from its members within an arena.
-   `infix_forward_create_manual(tramp, ret_t, arg_t, ...)`: Creates a forward trampoline from manually-built `infix_type` objects.
-   `infix_arena_destroy(arena)`: Frees an arena and all types that were allocated from it in a single operation.

## Learn More

*   **[Signature Reference](docs/signatures.md):** The complete guide to the signature mini-language.
*   **[Cookbook](docs/cookbook.md):** Practical, copy-pasteable recipes for common FFI tasks.
*   **[Internals](docs/internals.md):** A deep dive into the library's architecture.
*   **[Porting Guide](docs/porting.md):** Instructions for adding support for new architectures.
*   **[INSTALL.md](INSTALL.md):** Detailed build and integration instructions.

## License & Legal

`infix` is provided under multiple licenses to maximize its usability for all.

### Code License

Source code, including header files (`.h`) and implementation files (`.c`), is dual-licensed under the **Artistic License 2.0** or the **MIT License**. You may choose to use the code under the terms of either license.

See the [LICENSE-A2](LICENSE-A2) and/or [LICENSE-MIT](LICENSE-MIT) for the full text of both licenses.

### Documentation License

All standalone documentation (`.md`), explanatory text, Doxygen-style documentation blocks, comments, and code examples contained within this repository may be used, modified, and distributed under the terms of the **Creative Commons Attribution 4.0 International License (CC BY 4.0)**. I encourage you to share and adapt the documentation for any purpose (generating an API reference website, creating tutorials, etc.), as long as you give appropriate credit.

See the [LICENSE-CC](LICENSE-CC) for details.
