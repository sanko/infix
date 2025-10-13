# Changelog

All notable changes to this project will (I hope) be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

This is the initial public release of the `infix` FFI library.

### Added

- Core FFI Engine
    + Core JIT engine for generating forward-call (calling from your code into C) and reverse-call (creating C callbacks from your handlers) trampolines.
    + High-level Signature API for creating and managing trampolines from simple, human-readable strings (e.g., `"(int, *char) -> double"`).
    + Low-level Manual API for programmatic, arena-based creation of C types for performance-critical scenarios.

- Signature Language & Type System
    + Comprehensive signature language with support for all major C types:
        + Primitives: Both abstract (`int`, `long`) and fixed-width (`int32`, `uint64`).
        + Pointers: `*` for pointers to any type, including `*void`.
        + Structs: `{...}` for C `struct` definitions.
        + Unions: `<...>` for C `union` definitions.
        + Arrays: `[<size>:<type>]` for fixed-size arrays.
        + Function Pointers: `*((...) -> ...)` for describing and passing function pointers.
        + Enums: `e:<int_type>` for describing the underlying integer storage of an enum.
        + Special Numerics: `c[...]` for `_Complex` numbers and `v[...]` for SIMD vectors.
    + Support for variadic functions using the `;` separator (e.g., `"(*char; int, double) -> int"` for `printf`).
    + Support for packed structs with `!{...}` for 1-byte packing and `!N:{...}` for N-byte packing.

- Named Type Registry
    + A powerful registry for defining complex structs, unions, and type aliases once and reusing them by name (e.g., `@Point`, `@Node`).
    +   Automatically handles forward declarations and mutually recursive types, allowing complex data structures to be defined in any order.

- Security Features
    + Security-first design, hardened and validated through fuzz testing.
    + Strict W^X (Write XOR Execute) memory protection for all JIT-compiled code, with platform-native implementations (dual-mapping on Linux/BSD, `VirtualProtect`/`mprotect` elsewhere).
    + Guard Pages on freed trampoline memory to prevent use-after-free vulnerabilities by ensuring immediate and safe crashes.
    + Read-Only Contexts for reverse trampolines (callbacks) to protect against runtime memory corruption exploits.
    + Hardened against integer overflows in all type creation and layout calculation functions.

*   Dynamic Library & Globals API
    + Cross-platform API for loading dynamic/shared libraries (`.so`, `.dll`, `.dylib`).
    + Functions to look up symbols (functions or variables) by name within a loaded library.
    + `infix_read_global()` and `infix_write_global()` to access global variables from a library using the same signature system.

*   Introspection & Memory Management
    + Powerful introspection API to parse signatures and inspect C type memory layouts at runtime (size, alignment, and member offsets).
    + `infix_type_print()` to serialize a type graph back into a canonical signature string.
    + Efficient arena-based memory management for all type descriptions, simplifying cleanup and improving performance.
    + Support for custom memory allocators via preprocessor macros (`infix_malloc`, `infix_free`, etc.).

*   Platform Support
    + Initial cross-platform support for:
        + Architectures: x86-64 and AArch64 (ARM64).
        + ABIs: System V (Linux, macOS, BSDs), Windows x64, and AAPCS64 (standard ARM64).
        + Compilers: GCC, Clang, and MSVC.
        + Operating Systems: Rigorously tested on Linux, Windows, macOS, FreeBSD, OpenBSD, NetBSD, and Solaris.
    + Zero-dependency, unity-build design for easy integration into any C/C++ project.

*   Error Handling
    + Detailed, thread-safe error reporting via `infix_get_last_error()` for robust diagnostics.

[unreleased]: https://github.com/sanko/infix/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sanko/infix/releases/tag/v0.1.0
