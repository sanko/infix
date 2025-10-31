# Changelog

All notable changes to this project will (I hope) be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

Really sanding down the rough edges this time around.

 - Add `size_t` and `ssize_t` signature keywords
 - Add `char8_t`, `char16_t`, and `char32_t` aliases for integer types

## [0.1.0] - 2025-10-27

### Initial Public Release

This is the first tagged version of `infix`. It's all downhill from here.

### Added

Everything. It's brand new.

- Forward Trampolines:
  - "Bound" trampolines with a hardcoded target function for maximum performance
  - "Unbound" trampolines where the target function is provided at call-time for maximum flexibility
- Reverse Trampolines:
  - Callbacks: High-level API (`infix_reverse_create_callback`) for C/C++ developers, allowing the use of clean, type-safe C function signatures for handlers
  - Closures: Low-level API (`infix_reverse_create_closure`) for language binding authors and stateful callbacks, providing a generic handler signature and support for a `user_data` context pointer
- Cross-platform functions for loading shared libraries (`.so`, `.dll`, `.dylib`) and looking up symbols
- APIs for reading/writing exported global variables
- A powerful, human-readable string-based language to describe any C type or function signature. Support includes...
  - Primitives: `int`, `double`
  - Fixed-width integers: `int32`, `uint64`
  - Pointers: `*int`, `**void`
  - Structs: `{int, double}`
  - Packed structs with custom alignment: `!{...}` or `!4:{...}`
  - Unions: `<int, float>`
  - Arrays: `[10:char]`
  - Function Pointers: `(*((int)->void))`
  - Variadic functions using a semicolon separator: `(*char; int, double) -> int`
  - `_Complex` numbers: `c[double]`
  - SIMD Vectors: Comprehensive support for architecture-specific vectors, including:
    - `x86-64:` SSE, AVX, and AVX-512 (`__m128`, `__m256`, `__m512`)
    - `AArch64:` NEON and the Scalable Vector Extension (SVE)
    - Convenience keywords like `m256d` and `m512d` for common types.
  - Enums with an explicit underlying type: `e:int`
- Named Type Registry: A powerful system for defining and reusing complex types by name
  - Simple aliases: `@UserID = uint64;`
  - Recursive types: `@Node = { value: int, next: *@Node };`
  - Mutually recursive types via forward declarations: `@A; @B; ...`
- Manual API:
  A programmatic, arena-based API (`infix_type_create_struct`, etc.) for building `infix_type` objects without the string parser.
- Introspection API:
  A comprehensive suite of getter functions to inspect the layout of any type at runtime, including its size, alignment, and the name/offset/type of every member. This is ideal for building dynamic language bindings and data marshallers.

#### Security & Hardening
- W^X Memory Protection: JIT-compiled code is never writable and executable at the same time, enforced with platform-native APIs (`VirtualProtect`, `mprotect`, `MAP_JIT`).
- Guard Pages: Freed trampolines are made inaccessible to cause a safe, immediate crash on any use-after-free attempt.
- Read-Only Contexts: The internal metadata for reverse callbacks is made read-only after creation to prevent runtime memory corruption vulnerabilities.
- Integer Overflow Hardening: All API functions and internal calculations are hardened against integer overflows from malformed or malicious inputs.
- Comprehensive Test Suite: Over 30 unit and regression tests covering more than 300 assertions for ABI edge cases, memory lifecycle bugs, and security features.
- Fuzz Tested: The entire API surface, especially the signature parser and ABI classifiers, is continuously validated with `libFuzzer` and `AFL++` to find and fix potential crashes and hangs.

#### Performance & Memory Management
- High-Performance Design: The API separates the one-time JIT compilation cost from the near-native call-time overhead, making cached trampolines extremely fast.
- Arena Allocator: All type metadata is managed by a fast, efficient arena allocator, eliminating memory leaks and simplifying the manual API.
- Self-Contained Objects: Trampoline handles (`infix_forward_t`, `infix_reverse_t`) perform a deep copy of all necessary type information, making them fully self-contained and immune to use-after-free errors from other parts of the system.
- Zero Dependencies: The library is written in pure C11 and has no external library dependencies.

#### Platform Support
- Architectures: x86-64 and AArch64 (ARM64).
- ABIs:
  - System V AMD64 ABI (Linux, macOS, BSDs on x86-64)
  - Microsoft x64 Calling Convention (Windows on x86-64)
  - Procedure Call Standard for the ARM 64-bit Architecture (AAPCS64) on Linux, macOS, and Windows.
- Compilers: GCC, Clang, and Microsoft Visual C++ (MSVC).
- Operating Systems: Rigorously tested on Windows, Linux (Ubuntu), macOS, and multiple BSD variants.
- Runtime CPU Feature Detection: Safely runs code with advanced instruction sets (AVX2, AVX-512, SVE) by performing runtime checks, preventing crashes on unsupported hardware and enabling maximum performance where available.

[unreleased]: https://github.com/sanko/infix/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sanko/infix/releases/tag/v0.1.0
