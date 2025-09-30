# `infix`: A JIT-Powered FFI Library for C

`infix` is a modern, security-conscious Foreign Function Interface (FFI) library for C. It lets you call any C function—or create C callbacks—by describing them in a simple, human-readable string like `({int, *double}, *char) -> int`.

At its core, `infix` is a Just-in-Time (JIT) compiler that generates tiny, highly-optimized machine code wrappers at runtime. These "trampolines" handle all the low-level details of the target platform's calling convention (ABI) behind a clean, uniform API, making `infix` a powerful tool for embedding scripting languages, building plugin systems, and simplifying complex C interoperability.

## Key Features

*   **Simple, Powerful APIs:** Use the high-level **Signature API** to create trampolines from a single string, or drop down to the memory-safe **Manual API** for dynamic, performance-critical use cases.
*   **Powerful Introspection:** Parse signature strings to get detailed type information at runtime—including member names, offsets, pointer targets, and array sizes—ideal for dynamic data marshalling and building language bindings.
*   **Secure by Design:** `infix` is hardened against vulnerabilities and validated through extensive fuzz testing:
    *   **W^X Memory Protection:** JIT-compiled code is never writable and executable at the same time.
    *   **Guard Pages:** Freed trampolines are made inaccessible to prevent use-after-free bugs.
    *   **Read-Only Contexts:** Callback context data is made read-only to guard against runtime memory corruption.
*   **Stateful Callbacks Made Easy:** The reverse-call API is designed to make stateful callbacks simple and safe, even when the C library you're calling doesn't provide a `user_data` parameter.
*   **Zero Dependencies & Simple Integration:** `infix` uses a unity build, making integration into any C/C++ project trivial.

## Who is this for?

`infix` is designed for developers who need to bridge the gap between different codebases or language runtimes. You'll find it especially useful if you are:

*   **A Language Binding Author:** `infix` is the ideal engine for allowing a high-level language like Python, Ruby, Perl, or Lua to call C libraries. The introspectable type system and signature parser simplify the complex task of data marshalling.
*   **A Plugin System Architect:** Build a stable, ABI-agnostic plugin system. `infix` can provide the boundary layer, allowing you to load and call functions from shared libraries without tight coupling.
*   **A C/C++ Developer:** Dynamically call functions from system libraries (`user32.dll`, `libc.so.6`, etc.) without needing to link against them at compile time.
*   **A Security Researcher:** `infix` provides a powerful, fuzz-tested toolkit for analyzing and interacting with native code.

## Quick Start: The Two APIs

`infix` provides two APIs for creating trampolines. Most users should start with the Signature API.

### 1. The Signature API (Recommended)

This is the easiest and safest way to use the library. You describe a function in a string, and `infix` handles the rest.

**Example: Calling a Simple Function**
```c
#include <infix/infix.h>
#include <stdio.h>

// The C function we want to call dynamically.
int add_ints(int a, int b) {
    return a + b;
}

int main() {
    // 1. Describe the signature: int(int, int).
    const char* signature = "(int32, int32) -> int32";
    infix_forward_t* trampoline = NULL;

    // 2. Generate the trampoline. This is a one-time setup cost.
    infix_forward_create(&trampoline, signature);

    // 3. Prepare arguments. The args array holds *pointers* to the values.
    int a = 40, b = 2;
    void* args[] = { &a, &b };
    int result = 0;

    // 4. Get the callable function pointer and invoke it.
    infix_cif_func cif_func = (infix_cif_func)infix_forward_get_code(trampoline);
    cif_func((void*)add_ints, &result, args);

    printf("Result: %d\n", result); // Expected: 42

    // 5. Clean up.
    infix_forward_destroy(trampoline);
    return 0;
}
```

#### Signature API Cheat Sheet

> For a complete guide, see the **[Signature Language Reference](docs/signatures.md)**.

| Concept | Syntax Example | C Equivalent |
| :--- | :--- | :--- |
| **Primitives** | `int`, `double`, `uint64` | `int`, `double`, `uint64_t` |
| **Pointer** | `*char` | `char*` |
| **Array** | `[16:int]` | `int arr[16]` |
| **Struct** | `{int, double}` | `struct { int; double; }` |
| **Union** | `<int, double>` | `union { int; double; }` |
| **Packed Struct**| `!{char, int}` | `struct { char; int; } __attribute__((packed))` |
| **Function Ptr**| `*((int) -> void)` | `void (*func)(int)` |
| **Variadic** | `(*char; int)` | `const char*, int, ...` |

### 2. The Manual API (Advanced)

For performance-critical or highly dynamic applications, you can build type descriptions manually. This API is **exclusively arena-based** to guarantee memory safety.

**Example: Manually Describing a `Point` Struct**
```c
#include <infix/infix.h>
#include <stddef.h>

typedef struct { double x; double y; } Point;

int main() {
    // 1. Create an arena. All type objects will be allocated from here.
    infix_arena_t* arena = infix_arena_create(4096);

    // 2. Describe the members of the Point struct.
    infix_struct_member members[] = {
        infix_type_create_member("x", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(Point, x)),
        infix_type_create_member("y", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(Point, y))
    };

    // 3. Create the struct type from the arena.
    infix_type* point_type = NULL;
    infix_type_create_struct(arena, &point_type, members, 2);

    // Now 'point_type' can be used to generate a trampoline...

    // 4. Destroy the arena to free the 'point_type' and all other allocations.
    infix_arena_destroy(arena);
    return 0;
}
```

#### Manual API Cheat Sheet

<details>
<summary><strong>Click to expand the full Manual API reference</strong></summary>

**Arena Management**
| Function | Purpose |
| :--- | :--- |
| `infix_arena_create(size)` | Create a memory arena for fast allocations. |
| `infix_arena_alloc(arena, size, align)` | Allocate raw, uninitialized memory from the arena. |
| `infix_arena_calloc(arena, n, size, align)` | Allocate zero-initialized memory from the arena. |
| `infix_arena_destroy(arena)` | Free an arena and **all** objects allocated within it. |

**Type Creation**
| Function | Purpose |
| :--- | :--- |
| `infix_type_create_primitive(...)` | Get a static descriptor for `int`, `double`, etc. |
| `infix_type_create_pointer()` | Get a static descriptor for a generic `void*`. |
| `infix_type_create_void()` | Get a static descriptor for `void` (for return types). |
| `infix_type_create_struct(arena, ...)` | Build a struct type, calculating standard padding. |
| `infix_type_create_packed_struct(arena, ...)`| Build a struct type with explicit size and alignment. |
| `infix_type_create_union(arena, ...)` | Build a union type from its members. |
| `infix_type_create_array(arena, ...)` | Build an array type. |
| `infix_type_create_enum(arena, ...)` | Build an enum type from an underlying integer type. |
| `infix_type_create_complex(arena, ...)` | Build a `_Complex` number type. |
| `infix_type_create_pointer_to(arena, ...)`| Create a pointer type with introspection info. |
| `infix_type_create_member(...)` | Helper to create a member for a struct or union. |

**Trampoline Management**
| Function | Purpose |
| :--- | :--- |
| `infix_forward_create_manual(...)` | Generate a forward trampoline from manual `infix_type` objects. |
| `infix_forward_get_code(tramp)` | Get the callable `infix_cif_func` pointer from a forward trampoline. |
| `infix_forward_destroy(tramp)` | Free a forward trampoline and its executable memory. |
| `infix_reverse_create_manual(...)` | Generate a reverse trampoline (callback) from manual types. |
| `infix_reverse_get_code(ctx)` | Get the native C function pointer from a callback context. |
| `infix_reverse_get_user_data(ctx)` | Get the state pointer from within a callback handler. |
| `infix_reverse_destroy(ctx)` | Free a reverse trampoline, its stub, and its context. |

**Type Introspection**
| Function | Purpose |
| :--- | :--- |
| `infix_type_get_category(type)` | Get the fundamental kind of a type (struct, pointer, etc.). |
| `infix_type_get_size(type)` | Get the `sizeof` a type. |
| `infix_type_get_alignment(type)` | Get the `_Alignof` a type. |
| `infix_type_get_member_count(type)` | Get the number of members in a struct or union. |
| `infix_type_get_member(type, index)` | Get a specific member's info (name, type, offset) by index. |

</details>

## Powerful Introspection for Dynamic Data Marshalling

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
    if (infix_type_from_signature(&struct_type, &arena, profile_sig) != INFIX_SUCCESS) {
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

**Output:**

```
Inspecting struct layout for: {id:int32, score:double, name:*char}
Total size: 24 bytes, Alignment: 8 bytes
  - Member 'id': offset=0, size=4
  - Member 'score': offset=8, size=8
  - Member 'name': offset=16, size=8
```

This runtime layout information allows you to, for example, take a Python object and correctly pack its attributes into a C `UserProfile` struct in memory, byte by byte.

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

Full build instructions for `xmake`, `cmake`, `make`, and `nmake` are available in **[INSTALL.md](INSTALL.md)**.

Because `infix` uses a unity build, integration into an existing project is simple: You only need to add `src/infix.c` to your list of source files to compile and add the `include/` directory to your include paths.

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

All standalone documentation (`.md`), explanatory text, Doxygen-style documentation blocks, comments, and code examples contained within this repository may be used, modified, and distributed under the terms of the **Creative Commons Attribution 4.0 International License (CC BY 4.0)**. I encourage you to share and adapt the documentation for any purpose (generating an API reference website, creating tutorials, etc.), as long as you give appropriate credit.

See the [LICENSE-CC](LICENSE-CC) for details.
