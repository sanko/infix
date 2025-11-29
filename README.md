# `infix`: A JIT-powered FFI library for C

`infix` is a modern, lightweight C library that lets you call any C function or create C callbacks at runtime, using simple, human-readable strings to describe the function's signature.

It's designed to be the simplest way to add a dynamic Foreign Function Interface (FFI) to your project, whether you're building a language runtime, a plugin system, or just need to call functions from a dynamically loaded library.

[![CI](https://github.com/sanko/infix/actions/workflows/ci.yml/badge.svg)](#supported-platforms)

## Key Features

*   **Human-Readable Signatures:** Describe complex C functions with an intuitive string format (e.g., `"({double, double}, int) -> *char"`).
*   **Forward & Reverse Calls:** Call C functions ("forward") and create C function pointers that call back into your code ("reverse").
*   **Direct Marshalling API:** Build high-performance language bindings where the JIT compiler calls your object-unboxing functions directly, bypassing intermediate buffers.
*   **Simple Integration:** Add a single C file and a header directory to your project to get started. No complex dependencies.
*   **Type Registry:** Define, reuse, and link complex, recursive, and mutually-dependent structs by name.
*   **Security-First Design:** Hardened against vulnerabilities with Write XOR Execute (W^X) memory, guard pages, and fuzz testing.
*   **High Performance:** A Just-in-Time (JIT) compiler generates optimized machine code trampolines, making calls nearly as fast as a direct C call after the initial setup.

## Full Documentation

*   [Installation Guide](docs/INSTALL.md): How to build and integrate `infix`.
*   [API Quick Reference](docs/API.md): A complete reference for the public API.
*   [The FFI Cookbook](docs/cookbook.md): Practical, real-world examples and recipes.
*   [Signature Language Reference](docs/signatures.md): A deep dive into the signature string format.
*   [Porting Guide](docs/porting.md): Instructions for adding support for a new CPU architecture or ABI.
*   [Contributing Guide](CONTRIBUTING.md): How to contribute to the project.

---

## How It Works: A Quick Example

The heart of `infix` is its signature string. Here’s how you would call a simple C function:

```c
#include <infix/infix.h>
#include <stdio.h>

// The C function we want to call.
int add(int a, int b) { return a + b; }

int main() {
    // 1. Describe the function's signature as a string.
    const char* signature = "(int, int) -> int";

    // 2. Create a "trampoline"—a JIT-compiled function wrapper.
    infix_forward_t* trampoline = NULL;
    infix_forward_create(&trampoline, signature, (void*)add, NULL);
    infix_cif_func cif = infix_forward_get_code(trampoline);

    // 3. Prepare an array of *pointers* to the arguments.
    int a = 10, b = 32;
    void* args[] = { &a, &b };
    int result;

    // 4. Call the function through the trampoline.
    cif(&result, args);

    printf("Result: %d\n", result); // Output: Result: 42

    // 5. Clean up.
    infix_forward_destroy(trampoline);
    return 0;
}
```

## Creating Callbacks

`infix` can also generate native C function pointers that call back into your code. This is perfect for interfacing with C libraries that expect callbacks, like `qsort`.

```c
#include <infix/infix.h>
#include <stdlib.h>

// The C handler function for our callback.
int compare_integers(const void* a, const void* b) {
    return (*(const int*)a - *(const int*)b);
}

void run_qsort_example() {
    // 1. Describe the callback's signature.
    const char* cmp_sig = "(*void, *void) -> int";

    // 2. Create a reverse trampoline.
    infix_reverse_t* context = NULL;
    infix_reverse_create_callback(&context, cmp_sig, (void*)compare_integers, NULL);

    // 3. Get the JIT-compiled C function pointer.
    int (*my_comparator)(const void*, const void*) = infix_reverse_get_code(context);

    // 4. Use the generated callback with the C library function.
    int numbers[] = { 5, 1, 4, 2, 3 };
    qsort(numbers, 5, sizeof(int), my_comparator);
    // `numbers` is now sorted: [1, 2, 3, 4, 5]

    infix_reverse_destroy(context);
}
```

## High-Performance Language Bindings

If you are writing a binding for a language like Python, Perl, or Lua, `infix` offers a specialized direct marshalling API. This allows the JIT compiler to call your object unboxing functions ("marshallers") directly, eliminating the need to allocate intermediate C arrays.

```c
// A mock object from a scripting language.
typedef struct { int type; union { int i; double d; } val; } PyObject;

// A "Scalar Marshaller" converts a language object to a raw C value.
infix_direct_value_t marshal_int(void* obj_ptr) {
    PyObject* obj = (PyObject*)obj_ptr;
    return (infix_direct_value_t){ .i64 = obj->val.i };
}

void run_binding_example(void* target_func) {
    // 1. Define handlers for the arguments.
    infix_direct_arg_handler_t handlers[2] = {0};
    handlers[0].scalar_marshaller = marshal_int;
    handlers[1].scalar_marshaller = marshal_int;

    // 2. Create an optimized trampoline.
    infix_forward_t* trampoline;
    infix_forward_create_direct(&trampoline, "(int, int) -> void", target_func, handlers, NULL);

    // 3. Call it directly with an array of language objects.
    PyObject* args[] = { py_obj1, py_obj2 };

    // The JIT code calls `marshal_int` for each arg, then calls the target.
    infix_forward_get_direct_code(trampoline)(NULL, (void**)args);
}
```

## Getting Started

The easiest way to use `infix` is to add its source directly to your project.

1.  Copy the `src/` and `include/` directories into your project.
2.  Add `src/infix.c` to your build system's list of source files.
3.  Add the `include/` directory to your include paths.
4.  `#include <infix/infix.h>` in your code.

For more advanced build options, including building as a standalone library with CMake or xmake, see the [Building and Integration Guide](docs/INSTALL.md).

## Project Philosophy

`infix` is built on three core principles:

1.  **Security First:** An FFI library with a JIT is a prime target for vulnerabilities. We defend against these with a multi-layered approach, including strict W^X memory, hardened integer arithmetic, and continuous fuzz testing.
2.  **Performance by Design:** FFI overhead should be minimal. `infix` separates the one-time **generation cost** from the near-zero **call-time cost**, making it exceptionally fast in high-performance applications when trampolines are cached.
3.  **Simplicity and Portability:** Platform- and ABI-specific logic is strictly isolated, making the library easy to maintain, simple to integrate, and straightforward to port to new architectures.

## Platform Support

`infix` is rigorously tested on a wide array of operating systems, compilers, and architectures with every commit.

| OS           | Version     | Architecture | Compiler  | Status                                                                                                                                                                                               |
| :----------- | :---------- | :----------- | :-------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| DragonflyBSD | 6.4.0       | x86-64       | GCC       | ![dragonflybsd/x64/gcc](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=dragonflybsd-x86_64-gcc) |
| FreeBSD      | 15.0        | x86-64       | GCC       | ![freebsd/x86/gcc     ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=freebsd-x86_64-gcc) |
|              | 15.0        | AArch64      | GCC       | ![freebsd/a64/gcc     ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=freebsd-aarch64-gcc)     |
|              | 15.0        | RISC-V64     | GCC       | ![freebsd/r64/gcc     ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=freebsd-riscv64-gcc)     |
|              | 15.0        | x86-64       | Clang     | ![freebsd/x64/clang   ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=freebsd-x86_64-clang) |
|              | 15.0        | AArch64      | Clang     | ![freebsd/a64/clang   ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=freebsd-aarch64-clang)   |
|              | 15.0        | RISC-V64     | Clang     | ![freebsd/r64/clang     ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=freebsd-riscv64-clang)     |
| macOS        | Sequoia     | AArch64      | Clang     | ![macos/a64/clang     ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=macos-aarch64-clang) |
|              | Sequoia     | AArch64      | GCC       | ![macos/a64/gcc       ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=macos-aarch64-gcc)   |
| NetBSD       | 10.1        | AArch64      | GCC       | ![netbsd/a64/gcc      ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=netbsd-aarch64-gcc) |
|              | 10.1        | x86-64       | GCC       | ![netbsd/x64/gcc      ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=netbsd-x86_64-gcc)   |
| OmniOS       | r151054     | x86-64       | GCC       | ![omnios/x64/gcc      ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=omnios-x86_64-gcc) |
| OpenBSD      | 7.8         | AArch64      | Clang     | ![openbsd/a64/clang   ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=openbsd-aarch64-clang) |
|              | 7.8         | AArch64      | GCC       | ![openbsd/a64/gcc     ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=openbsd-aarch64-egcc) |
|              | 7.8         | x86-64       | Clang     | ![openbsd/x64/clang   ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=openbsd-x86_64-clang) |
|              | 7.8         | x86-64       | Clang     | ![openbsd/x64/clang   ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=openbsd-x86_64-egcc) |
|              | 7.8         | RISC-V64     | Clang     | ![openbsd/r64/clang   ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=opensd-riscv64-clang)     |
|              | 7.8         | RISC-V64     | GCC       | ![openbsd/r64/gcc     ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=openbsd-riscv64-egcc) |
| Solaris      | 11.4        | x86-64       | GCC       | ![solaris/x64/gcc     ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=solaris-x86_64-gcc) |
| Ubuntu       | 24.04       | AArch64      | Clang     | ![ubuntu/a64/clang    ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=ubuntu-aarch64-clang) |
|              | 24.04       | AArch64      | GCC       | ![ubuntu/a64/gcc      ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=ubuntu-aarch64-gcc) |
|              | 24.04       | x86-64       | Clang     | ![ubuntu/x64/clang    ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=ubuntu-x86_64-clang) |
|              | 24.04       | x86-64       | GCC       | ![ubuntu/x64/gcc      ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=ubuntu-x86_64-gcc) |
| Windows      | Server 2025 | AArch64      | Clang     | ![windows/a64/clang   ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=windows-aarch64-clang) |
|              | Server 2025 | AArch64      | GCC       | ![windows/a64/gcc     ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=windows-aarch64-gcc) |
|              | Server 2025 | AArch64      | MSVC      | ![windows/a64/msvc    ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=windows-aarch64-msvc) |
|              | Server 2025 | x86-64       | Clang     | ![windows/x64/clang   ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=windows-x86_64-clang) |
|              | Server 2025 | x86-64       | GCC       | ![windows/x64/gcc     ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=windows-x86_64-gcc) |
|              | Server 2025 | x86-64       | MSVC      | ![windows/x64/msvc    ](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fsankorobinson.com%2Finfix%2Fstatus%2Fstatus.json&style=for-the-badge&label=%20&query=windows-x86_64-msvc) |

In addition to the CI platforms tested here on Github, I can verify infix builds and passes unit tests on Android/Termux.

## Licenses

To maximize usability for all, `infix` is dual-licensed under the [Artistic License 2.0](LICENSE-A2)  and the [MIT License](LICENSE-MIT). You may choose to use the code under the terms of either license.

At your discretion, all standalone documentation (`.md`), explanatory text, Doxygen-style documentation blocks, comments, and code examples contained within this repository may be used, modified, and distributed under the terms of the  [Creative Commons Attribution 4.0 International License (CC BY 4.0)](LICENSE-CC). I encourage you to share and adapt the documentation for any purpose (generating an API reference website, creating tutorials, etc.), as long as you give appropriate credit.
