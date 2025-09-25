# `infix`: A JIT-Powered FFI Library for C

`infix` is a modern FFI library for C that lets you call any C function—or create C callbacks—by describing them in a simple string like `"{i,d*},c*=>i"`.

At its core, this is a Just-in-Time (JIT) compiler that generates tiny, highly-optimized machine code that wraps all the low-level details of the target platform's calling convention in a uniform API. This makes `infix` a powerful tool for embedding scripting languages, building plugin systems, and simplifying complex C interoperability.

## Quick Start: Calling a Shared Library

This example demonstrates a core FFI use case: dynamically loading a shared library (`.dll` or `.so`), retrieving a function pointer from it, and calling that function.

First, imagine we have a simple shared library, `libgreeting`, that exports one function:

```c
// In libgreeting.so / greeting.dll
#include <stdio.h>

void say_hello(const char* name) {
    printf("Hello, %s!\n", name);
}
```

Our main application can use `infix` to load and call this function at runtime:

```c
#include <infix.h>
#include <stdio.h>

// Platform-specific headers for dynamic library loading
#if defined(_WIN32)
#include <windows.h>
#else
#include <dlfcn.h>
#endif

int main() {
    // 1. Dynamically load the shared library.
#if defined(_WIN32)
    HMODULE lib_handle = LoadLibraryA("greeting.dll");
#else
    void* lib_handle = dlopen("./libgreeting.so", RTLD_LAZY);
#endif
    if (!lib_handle) {
        fprintf(stderr, "Error: Could not load shared library.\n");
        return 1;
    }

    // 2. Get a pointer to the function we want to call.
#if defined(_WIN32)
    void* say_hello_ptr = (void*)GetProcAddress(lib_handle, "say_hello");
#else
    void* say_hello_ptr = dlsym(lib_handle, "say_hello");
#endif
    if (!say_hello_ptr) {
        fprintf(stderr, "Error: Could not find function 'say_hello'.\n");
        return 1;
    }

    // 3. Create an infix trampoline for the function's signature: void(const char*)
    infix_forward_t* trampoline = NULL;
    infix_forward_create(&trampoline, "c*=>v");

    // 4. Prepare arguments and call the function via the trampoline.
    infix_cif_func cif = (infix_cif_func)infix_forward_get_code(trampoline);
    const char* name = "World";
    void* args[] = { &name };
    cif(say_hello_ptr, NULL, args); // The return value pointer is NULL for void functions.

    // 5. Clean up.
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
-   **Powerful Introspection:** Parse signature strings to get detailed type information at runtime, ideal for data marshalling or serialization.
-   **Secure by Design:** `infix` adheres to strict security principles, validated through extensive fuzzing:
    -   **W^X Memory Protection:** JIT-compiled code is never writable and executable at the same time.
    -   **Guard Pages:** Freed trampolines are made inaccessible to prevent use-after-free bugs.
    -   **Read-Only Contexts:** Callback context data is made read-only after initialization to guard against runtime memory corruption.
-   **Cross-Platform ABI Support:** Correctly handles calling conventions for **x86-64** (System V, Windows) and **AArch64** (Standard AAPCS64, Apple, and Windows variants).
-   **Zero Dependencies & Simple Integration:** `infix` is a header-only library with a unity build, making integration trivial.

## API Overview

`infix` provides two distinct APIs for creating trampolines: a high-level **Signature API** and a low-level **Manual API**.

### Core Concepts

-   **`infix_type`**: The central data structure that describes any C type.
-   **`infix_cif_func`**: A generic function pointer for invoking a forward trampoline: `void (*infix_cif_func)(void* target_function, void* return_value, void** args);`
-   **`infix_reverse_t`**: An opaque handle to a callback's context. A pointer to this context (`infix_context_t*`) is **always passed as the first argument** to your C callback handler, allowing you to access user data and other metadata.

### Arena Memory Allocator

`infix` exposes an efficient arena allocator. An arena pre-allocates a single memory block and serves allocation requests by "bumping" a pointer. This is used internally for parsing and is available for performance-critical applications.

### Introspection and Type Parsing

You can parse signature strings to get detailed information about types at runtime, ideal for data marshalling or building C structs dynamically.

-   **`infix_signature_parse()`**: Parses a full function signature into its `infix_type` components.
-   **`infix_type_from_signature()`**: Parses a string representing a single data type.

Both functions allocate the resulting `infix_type` graph from an arena and give you ownership. You can then traverse the `infix_type` struct to inspect its `size`, `alignment`, `category`, and members.

## Building the Project

The project uses **xmake** as its primary build system, but also includes a powerful Perl script for advanced tasks and simple Makefiles for basic compilation.

### Prerequisites

-   A C17-compatible compiler (GCC, Clang, or MSVC).
-   A build system (choose one but they're all optional; you might want to build it by hand, idk)
    -   Perl v5.40+ (includes support for the fuzzers and other advanced developer stuff)
    -   [xmake](https://xmake.io/)
    -   GNU make (use `Makefile`)
    -   NMake (use `Makefile.win`)
    -   CMake

For instructions on building and using `infix` in your projects, see (INSTALL.md)[INSTALL.md].

## The Signature API (Recommended)

This API generates trampolines from a simple string: `"arg1,arg2;variadic_arg=>ret_type"`.

### Signature Language Reference

#### Primitives

| Specifier | C Type | Specifier | C Type |
| :--- | :--- | :--- | :--- |
| `v` | `void` | `x` | `int64_t` |
| `b` | `bool` | `y` | `uint64_t` |
| `c` | `char` | `n` | `__int128_t` |
| `a` | `int8_t` | `o` | `__uint128_t` |
| `h` | `uint8_t` | `f` | `float` |
| `s` | `int16_t` | `d` | `double` |
| `t` | `uint16_t`| `e` | `long double`|
| `i` | `int32_t` | `l` | `long` |
| `j` | `uint32_t`| `m` | `unsigned long` |

#### Constructs

-   **Pointer (`*`)**: A postfix modifier that can be chained.
    -   `i*` corresponds to `int*`.
    -   `v**` corresponds to `void**`.

-   **Array (`[...]`)**: `[size]type`. Defines a fixed-size array.
    -   `[10]i` corresponds to `int[10]`.
    -   `[5]{i,d}` corresponds to `struct { int; double; }[5]`.

-   **Grouping (`(...)`)**: Overrides the default precedence to group a type before applying modifiers. This is essential for declaring pointers to arrays.
    -   `([10]i)*` corresponds to `int (*)[10]`.

-   **Struct (`{...}`) and Union (`<...>`):** A comma-separated list of member types.
    -   `{i,d}` corresponds to `struct { int; double; }`.
    -   `<f,y>` corresponds to `union { float; uint64_t; }`.

-   **Named Fields (`:`)**: Optionally, members of structs and unions can be named for introspection.
    -   `{id:j, name:c*}` corresponds to `struct { unsigned int id; const char* name; }`.

-   **Packed Struct (`p(...)`)**: `p(size,align){type@offset,...}`. Defines a struct with an explicit, non-standard memory layout. `size` and `align` are byte values, and each member is followed by `@` and its byte offset.
    -   `p(5,1){c@0,i@1}` corresponds to `struct __attribute__((packed)) { char c; int i; }`.

-   **Function Pointer (`(...)`)**: The signature mirrors the main format, nested within parentheses.
    -   `(i,d=>v)*` corresponds to `void (*)(int, double)`.

### Signature Examples Table

| C Function Signature | Signature String | Explanation |
| :--- | :--- | :--- |
| `int max(int a, int b);` | `"i,i=>i"` | Two `int` args, `int` return. |
| `void print_point(const Point* p);` <br> `struct Point { int x; double y; }` | `"{i,d}*=>v"` | A pointer `*` to a struct `{i,d}` as an argument, `void` return. |
| `int printf(const char* format, ...);` | `"c*;=>i"` | A `char*` (`c*`), then variadic args (indicated by `;`), `int` return. |
| `void register_callback(void (*cb)(int));` | `"(i=>v)*=>v"` | The argument is a pointer `*` to a function `(i=>v)`. |
| `User** find_users(int* count);` <br> `struct User { const char* name; int id; }` | `i*=>{name:c*,id:i}**` | An `int*` argument. Returns a pointer-to-pointer `**` to a named struct. |

---

## The Manual API (Advanced)

This API gives you fine-grained control by requiring you to build the `infix_type` object graph manually. It is **exclusively arena-based** to ensure memory safety.

### Memory Ownership Model

The manual API uses a simple and safe arena-based memory model.
1.  You create an `infix_arena_t` at the start of your task.
2.  All `infix_type` objects created with `infix_type_create_struct`, `_union`, or `_array` are allocated from this arena.
3.  When you are finished with the types and any trampolines created from them, you call `infix_arena_destroy` **once** to free all associated memory.
4.  You **must not** call a `_destroy` function on individual types created from an arena.

### Manual API Function List

This is a partial list of the core functions. See [`infix.h`](include/infix.h) for the full documentation.

-   `infix_type_create_primitive()`: Gets a static descriptor for a C primitive.
-   `infix_type_create_struct()`: Creates a new struct type from an array of members, allocating from an arena.
-   `infix_forward_create_manual()`: JIT-compiles a forward call trampoline from manual `infix_type`s.
-   `infix_forward_destroy()`: Frees a forward trampoline.

---

## Advanced Topics

### Customizable Memory Management

You can redirect all of `infix`'s internal memory allocations by defining the following macros before including `infix.h`: `infix_malloc`, `infix_calloc`, `infix_realloc`, `infix_free`, `infix_memcpy`, `infix_memset`.

**...why?**
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

Most `infix` API functions return an `infix_status` enum. A successful operation will always return `INFIX_SUCCESS`. Any other value indicates an error.

```c
infix_forward_t* trampoline = NULL;
infix_status status = infix_forward_create(&trampoline, "invalid signature");

if (status != INFIX_SUCCESS) {
    // Handle the error. For example:
    if (status == INFIX_ERROR_INVALID_ARGUMENT)
        fprintf(stderr, "Error: The signature string was malformed.\n");
    else if (status == INFIX_ERROR_ALLOCATION_FAILED)
        fprintf(stderr, "Error: A memory allocation failed.\n");
    // ...
}
```

### Callbacks (Reverse Calls)

A key feature of `infix` is the ability to create C function pointers from your own C functions. This is essential for interfacing with libraries that use callbacks.

**Your C handler's signature will always receive the `infix_context_t*` context as its first argument.** The subsequent arguments will match the signature string you provide.

**Example: A Stateful Callback for a C Library**

Imagine a simple C library that processes a list of numbers but doesn't provide a way to pass user state to the callback.

```c
// The C library's required callback type
typedef void (*item_processor_t)(int item_value);
// The C library's function
void process_list(int* items, int count, item_processor_t func);
```

With `infix`, you can easily adapt a stateful handler to this stateless API.

```c
#include <infix.h>
#include <stdio.h>

// Your application state
typedef struct { int total; } AppState;

// Your C handler. Note the `context` parameter.
void my_handler(infix_context_t* context, int item) {
    // Retrieve your state from the context
    AppState* state = (AppState*)infix_reverse_get_user_data(context);
    state->total += item;
    printf("Handler processed item %d, new total is %d\n", item, state->total);
}

int main() {
    AppState my_app_state = {0};

    // 1. Create the reverse trampoline for the signature the library expects: "i=>v"
    //    Pass your handler and a pointer to your state.
    infix_reverse_t* rt = NULL;
    infix_reverse_create(&rt, "i=>v", (void*)my_handler, &my_app_state);

    // 2. Get the native function pointer and pass it to the C library.
    item_processor_t callback_ptr = (item_processor_t)infix_reverse_get_code(rt);
    int items[] = {10, 20, 30};
    process_list(items, 3, callback_ptr);

    printf("Final total from AppState: %d\n", my_app_state.total); // Expected: 60

    infix_reverse_destroy(rt);
    return 0;
}
```

### Platform Detection Macros

`infix.h` automatically detects the build environment, if you require something similar, include `src/common/infix_config.h` which defines a set of preprocessor macros that you can use for platform-specific code.

-   **`INFIX_OS_*`**: (`INFIX_OS_WINDOWS`, `INFIX_OS_MACOS`, `INFIX_OS_LINUX`, etc.) for the operating system.
-   **`INFIX_ARCH_*`**: (`INFIX_ARCH_X64`, `INFIX_ARCH_AARCH64`) for the CPU architecture.
-   **`INFIX_ABI_*`**: (`INFIX_ABI_WINDOWS_X64`, `INFIX_ABI_SYSV_X64`, `INFIX_ABI_AAPCS64`) for the Application Binary Interface.
-   **`INFIX_COMPILER_*`**: (`INFIX_COMPILER_MSVC`, `INFIX_COMPILER_CLANG`, `INFIX_COMPILER_GCC`) for the compiler.
-   **`INFIX_ENV_*`**: (`INFIX_ENV_POSIX`, `INFIX_ENV_MINGW`) for specific build environments.

## Learn More

*   **[Cookbook](./docs/cookbook.md):** Practical, copy-pasteable recipes for common FFI tasks.
*   **[Internals](./docs/internals.md):** A deep dive into the library's architecture for maintainers and contributors.
*   **[Porting Guide](./docs/porting.md):** A brief document with basic instructions to add new architectures.

## License & Legal

`infix` is provided under multiple licenses to maximize its usability for all.

### Code License

Source code, including header files (`.h`) and implementation files (`.c`), is dual-licensed under the **Artistic License 2.0** or the **MIT License**. You may choose to use the code under the terms of either license.

See the [LICENSE-A2](LICENSE-A2) and/or [LICENSE-MIT](LICENSE-MIT) for the full text of both licenses.

### Documentation License

All standalone documentation (`.md`), explanatory text, Doxygen-style documentation blocks, comments, and code examples contained within this repository may be used, modified, and distributed under the terms of the **Creative Commons Attribution 4.0 International License (CC BY 4.0)**. I encourage you to share and adapt the documentation for any purpose (generating an API reference website, creating tutorials, etc.), as long as you
give appropriate credit.

See the [LICENSE-CC](LICENSE-CC) for details.
