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
    ffi_trampoline_t* trampoline = NULL;
    ffi_create_forward_trampoline_from_signature(&trampoline, "c*=>v");

    // 4. Prepare arguments and call the function via the trampoline.
    ffi_cif_func cif = (ffi_cif_func)ffi_trampoline_get_code(trampoline);
    const char* name = "World";
    void* args[] = { &name };
    cif(say_hello_ptr, NULL, args); // The return value pointer is NULL for void functions.

    // 5. Clean up.
    ffi_trampoline_free(trampoline);
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

-   **`ffi_type`**: The central data structure that describes any C type.
-   **`ffi_cif_func`**: A generic function pointer for invoking a forward trampoline: `void (*ffi_cif_func)(void* target_function, void* return_value, void** args);`
-   **`ffi_reverse_trampoline_t`**: An opaque handle to a callback's context. A pointer to this context is **always passed as the first argument** to your C callback handler, allowing you to access user data and other metadata.

### Arena Memory Allocator

`infix` exposes an efficient arena allocator. An arena pre-allocates a single memory block and serves allocation requests by "bumping" a pointer. This is used internally for parsing and is available for performance-critical applications.

### Introspection and Type Parsing

You can parse signature strings to get detailed information about types at runtime, ideal for data marshalling or building C structs dynamically.

-   **`ffi_signature_parse()`**: Parses a full function signature into its `ffi_type` components.
-   **`ffi_type_from_signature()`**: Parses a string representing a single data type.

Both functions allocate the resulting `ffi_type` graph from an arena and give you ownership. You can then traverse the `ffi_type` struct to inspect its `size`, `alignment`, `category`, and members.

## Building the Project

The project uses **xmake** as its primary build system, but also includes a powerful Perl script for advanced tasks and simple Makefiles for basic compilation.

### Prerequisites

-   A C17-compatible compiler (GCC, Clang, or MSVC).
-   A build system (choose one but they're all optional; you might want to build it by hand, idk)
    -   Perl v5.40+ (includes support for the fuzzers and other advanced developer stuff)
    -   [xmake](https://xmake.io/)
    -   GNU make (use `Makefile`)
    -   NMake (use `Makefile.win`)

### Common Build Commands

-   **Configure and Build the Library:**

    ```bash
    # Build the static library
    xmake

    # Run all tests
    xmake test

    # Run the advanced perl based builder
    perl build.pl help
    ```

## Integrating `infix` into Your Project

You can integrate `infix` into your own projects using several methods, depending on your build system.

### Using xmake (Recommended)

If your project uses xmake, add `infix` as a remote package dependency in your `xmake.lua`.

```lua
    -- Your project's xmake.lua
    set_project("my_awesome_app")
    set_version("1.0.0")
    set_languages("c17")

    -- 1. Tell xmake where to find the infix project
    add_requires("infix", {git = "https://github.com/sanko/infix.git"})

    -- Define your application's target
    target("my_awesome_app")
        set_kind("binary")
        add_files("src/*.c")

        -- 2. Link against the "infix" static library target
        add_deps("infix")
```

Now, you can simply include the header (`#include <infix.h>`) in your source files and build your project with `xmake`.

### Manual Integration (CMake, Make, etc.)

If you use a different build system like Make, CMake, or a simple editor setup, you can build `infix` as a static library first and then link it.

1.  **Build the `infix` Static Library** using the Perl script, xmake, or make/nmake. This will create `libinfix.a` (or `infix.lib`).

2.  **Configure Your Project** to find the header and library files.

##### Using on the Command Line (GCC/Clang)

Use the `-I` flag for the include directory, `-L` for the library directory, and `-l` to link the library.

```bash
# Assuming infix was built with the Perl script
gcc my_app.c \
    -I/path/to/infix/include \
    -L/path/to/infix/build_lib \
    -linfix \
    -o my_app
```

##### Using in Visual Studio Code

First, build the `infix` library. Then, create a `.vscode` directory in your project's root and add these two files:

1.  **`c_cpp_properties.json`** (for IntelliSense)
    This tells the C/C++ extension where to find `infix.h`.

    ```json
    {
        "configurations": [
            {
                "name": "Linux",
                "includePath": [
                    "${workspaceFolder}/**",
                    "${workspaceFolder}/libs/infix/include" // <-- Path to infix include dir
                ],
                "cStandard": "c17"
            }
        ],
        "version": 4
    }
    ```

2.  **`tasks.json`** (for Building)
    This defines a build task that compiles your code and links against `infix`.

    ```json
    {
        "version": "2.0.0",
        "tasks": [
            {
                "label": "build with infix",
                "type": "shell",
                "command": "gcc",
                "args": [
                    "-std=c17", "-g", "${file}",
                    "-I${workspaceFolder}/libs/infix/include",
                    "-L${workspaceFolder}/libs/infix/build_lib",
                    "-linfix",
                    "-o", "${fileDirname}/${fileBasenameNoExtension}"
                ],
                "group": { "kind": "build", "isDefault": true }
            }
        ]
    }
    ```
    You can now build by pressing `Ctrl+Shift+B` (or `Cmd+Shift+B` on macOS).

##### Using in CMake

Create an `IMPORTED` target for the pre-built `infix` library.

```cmake
# Create an IMPORTED target for the pre-built infix library
add_library(infix STATIC IMPORTED)
set_target_properties(infix PROPERTIES
    IMPORTED_LOCATION "/path/to/build_lib/libinfix.a" # Or .lib
    INTERFACE_INCLUDE_DIRECTORIES "/path/to/infix/include"
)

# Link your executable against it
target_link_libraries(my_app PRIVATE infix)
```

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

This API gives you fine-grained control by requiring you to build the `ffi_type` object graph manually.

### Memory Ownership Model

-   **Caller Owns**: You must free any `ffi_type` created with `ffi_type_create_struct`, `_union`, or `_array` by calling `ffi_type_destroy`. You must also free any trampoline handle with its corresponding `_free` function.
-   **Library Owns**: The library takes ownership of the `members` array passed to `ffi_type_create_struct` *only on success*. On failure, you must free it.
-   **Static Types**: Types from `ffi_type_create_primitive`, `_pointer`, or `_void` are static singletons and **must not** be freed.

### Manual API Function List

This is a partial list of the core functions. See [`infix.h`](include/infix.h) for the full documentation.

-   `ffi_type_create_primitive()`: Gets a static descriptor for a C primitive.
-   `ffi_type_create_struct()`: Creates a new struct type from an array of members.
-   `generate_forward_trampoline()`: JIT-compiles a forward call trampoline from manual `ffi_type`s.
-   `ffi_trampoline_free()`: Frees a forward trampoline.

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

Most `infix` API functions return an `ffi_status` enum. A successful operation will always return `FFI_SUCCESS`. Any other value indicates an error.

```c
ffi_trampoline_t* trampoline = NULL;
ffi_status status = ffi_create_forward_trampoline_from_signature(&trampoline, "invalid signature");

if (status != FFI_SUCCESS) {
    // Handle the error. For example:
    if (status == FFI_ERROR_INVALID_ARGUMENT)
        fprintf(stderr, "Error: The signature string was malformed.\n");
    else if (status == FFI_ERROR_ALLOCATION_FAILED)
        fprintf(stderr, "Error: A memory allocation failed.\n");
    // ...
}
```

### Callbacks (Reverse Calls)

A key feature of `infix` is the ability to create C function pointers from your own C functions. This is essential for interfacing with libraries that use callbacks.

**Your C handler's signature will always receive the `ffi_reverse_trampoline_t*` context as its first argument.** The subsequent arguments will match the signature string you provide.

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
void my_handler(ffi_reverse_trampoline_t* context, int item) {
    // Retrieve your state from the context
    AppState* state = (AppState*)ffi_reverse_trampoline_get_user_data(context);
    state->total += item;
    printf("Handler processed item %d, new total is %d\n", item, state->total);
}

int main() {
    AppState my_app_state = {0};

    // 1. Create the reverse trampoline for the signature the library expects: "i=>v"
    //    Pass your handler and a pointer to your state.
    ffi_reverse_trampoline_t* rt = NULL;
    ffi_create_reverse_trampoline_from_signature(&rt, "i=>v", (void*)my_handler, &my_app_state);

    // 2. Get the native function pointer and pass it to the C library.
    item_processor_t callback_ptr = (item_processor_t)ffi_reverse_trampoline_get_code(rt);
    int items[] = {10, 20, 30};
    process_list(items, 3, callback_ptr);

    printf("Final total from AppState: %d\n", my_app_state.total); // Expected: 60

    ffi_reverse_trampoline_free(rt);
    return 0;
}
```

### Platform Detection Macros

`infix.h` automatically detects the build environment and defines a set of preprocessor macros that you can use for platform-specific code.

-   **`FFI_OS_*`**: (`FFI_OS_WINDOWS`, `FFI_OS_MACOS`, `FFI_OS_LINUX`, etc.) for the operating system.
-   **`FFI_ARCH_*`**: (`FFI_ARCH_X64`, `FFI_ARCH_AARCH64`) for the CPU architecture.
-   **`FFI_ABI_*`**: (`FFI_ABI_WINDOWS_X64`, `FFI_ABI_SYSV_X64`, `FFI_ABI_AAPCS64`) for the Application Binary Interface.
-   **`FFI_COMPILER_*`**: (`FFI_COMPILER_MSVC`, `FFI_COMPILER_CLANG`, `FFI_COMPILER_GCC`) for the compiler.
-   **`FFI_ENV_*`**: (`FFI_ENV_POSIX`, `FFI_ENV_MINGW`) for specific build environments.

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
