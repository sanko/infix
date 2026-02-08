# Changelog

All notable changes to `infix` will (I hope) be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added `TARGET_DIRECT_TRAMPOLINE_GENERATOR` to the regression tester in `t/850_regression_cases.c` to support debugging and preventing regressions in the direct marshalling pipeline.

### Fixed

- Fixed a memory leak in `_infix_forward_create_direct_impl` where the `ref_count` of the newly created trampoline handle was not being initialized. This caused the handle to never be freed during destruction as the library incorrectly assumed other references existed.

## [0.1.5] - 2026-02-06

This release expands platform stability. Focus was on SEH and DWARF unwinding, float16 and AVX-512 vector types.

### Added

- Added support for half-precision floating-point (`float16`).
- Implemented C++ exception propagation through JIT frames on Linux (x86-64 and ARM64) using manual DWARF `.eh_frame` generation and `__register_frame`.
- Implemented Structured Exception Handling (SEH) for Windows x64 and ARM64 for C++ exception propagation through trampolines.
- Added `infix_forward_create_safe` API to establish an exception boundary that catches native exceptions and returns a dedicated error code (`INFIX_CODE_NATIVE_EXCEPTION`).
- Added support for 256-bit (AVX) and 512-bit (AVX-512) vectors in the System V ABI.
- Added support for receiving bitfield structs in reverse call trampolines.
- Added trampoline caching. Identical signatures and targets now share the same JIT-compiled code and metadata via internal reference counting, significantly reducing memory overhead and initialization time.
- Added a new opt-in build mode (`--sanity`) that emits extra JIT instructions to verify stack pointer consistency around user-provided marshaller calls, making it easier to debug corrupting language bindings.
- Added `t/405_simd_vectors_avx.c`, `t/406_simd_forward.c`, `t/407_float16.c`, and `t/902_cache_deduplication.c` to the test suite.

### Changed

- Unified platform and compiler detection macros into a consistent `INFIX_*` namespace (e.g., `INFIX_OS_LINUX`, `INFIX_ARCH_X64`, `INFIX_COMPILER_GCC`) throughout the codebase.
- Updated `infix_executable_make_executable` and internal layout structures to track trampoline prologue sizes, necessary for SEH and DWARF registration.
- Explicitly enabled 16-byte stack alignment in Windows x64 trampolines to ensure SIMD compatibility.
- Updated `infix_type_create_vector` to use the vector's full size for its natural alignment (e.g., 32-byte alignment for `__m256`).
- Refined the Windows x64 ABI to pass all vector types by reference (pointer in GPR). This ensures compatibility with MSVC which expects even 128-bit vectors to be passed via pointer in many scenarios, while still returning them by value in `XMM0`.
- Move to a pre-calculated hash field in `_infix_registry_entry_t`. Lookups and rehashing now use this stored hash, significantly reducing string hashing overhead during type resolution and registry scaling.
- Optimized Type Registry memory management: Internal hash table buckets are now heap-allocated and freed during rehashes, preventing memory "leaks" within the registry's arena.
- Improve C++ Mangling Support:
    - Itanium (GCC/Clang): Implemented full substitution support (`S_`, `S0_`, etc.) for complex or repeated types.
    - MSVC: Implemented type back-references (`0-9`) for parameter lists.

### Fixed

- Corrected an ARM64 bug in `emit_arm64_ldr_vpr` and `emit_arm64_str_vpr` where boolean conditions were being passed instead of actual byte sizes, causing data truncation for floating-point values in the direct marshalling path.
- Fixed MSVC ARM: SEH XDATA layout to follow the architecture's specification exactly, enabling reliable exception handling on Windows on ARM.
- Hardened instruction cache invalidation on ARM64 Linux/BSD with a robust manual fallback using assembly (`dc cvau`, `ic ivau`, etc.), ensuring generated code is immediately visible to the CPU.
- Fixed the DWARF `.eh_frame` generation for ARM64 Linux `FORWARD` trampolines, correcting the instruction sequence and offsets to enable reliable C++ exception propagation.
- Corrected a performance issue on x64 by adding `vzeroupper` calls in epilogues when AVX instructions are potentially used, avoiding transition penalties.
- Fixed bitfield parsing logic to correctly handle colons in namespaces vs bitfield widths.
- Fixed missing support for 256-bit and 512-bit vectors in System V reverse trampolines.
- Rewrote `_layout_struct` in `src/core/types.c` to correctly handle bitfields larger than 8 bits and ensures `bit_offset` is always within the correct byte, matching standard C (well, GNU) compiler packing behavior.
- Fixed a bug in the SysV recursive classifier that was incorrectly applying strict natural alignment checks to bitfield members. This was causing structs containing bitfields to be unnecessarily passed on the stack instead of in registers.

## [0.1.4] - 2026-01-17

This release focuses on SIMD vector support and critical platform-specific stability fixes for macOS (both Intel and Apple Silicon), and improving internal code hygiene.

### Added

- Added `infix_get_version` and `infix_version_t` to the public API. This allows applications to query the semantic version of the library at runtime.
- Added `infix_registry_clone` to support deep-copying type registries for thread-safe interpreter cloning.
- Added `t/404_simd_vectors.c`: new unit tests for 128-bit SIMD vectors.
  - Currently targeting reverse callbacks to verify correct register marshalling.
- Introduced `INFIX_API` and `INFIX_INTERNAL` macros to explicitly control symbol visibility.

### Changed

- The JIT memory allocator on Linux now uses `memfd_create` (on kernels 3.17+) to create anonymous file descriptors for dual-mapped W^X memory. This avoids creating visible temporary files in `/dev/shm` and improves hygiene and security. On FreeBSD, `SHM_ANON` is now used.
- On dual-mapped platforms (Linux/BSD), the Read-Write view of the JIT memory is now **unmapped immediately** after code generation. This closes a security window where an attacker with a heap read/write primitive could potentially modify executable code by finding the stale RW pointer.
- The library now builds with hidden symbol visibility by default on supported compilers (GCC/Clang). Only public API functions (`infix_*`) are exported. Internal functions (`_infix_*`) are now hidden, preventing symbol collisions and ABI leakage when `infix` is linked statically into a shared library.
- `infix_library_open` now uses `RTLD_LOCAL` instead of `RTLD_GLOBAL` on POSIX systems. This prevents symbols from loaded libraries from polluting the global namespace and causing conflicts with other plugins or the host application.

### Fixed

- Fixed stack corruption on macOS ARM64 (Apple Silicon). `long double` on this platform is 8 bytes (an alias for `double`), unlike standard AAPCS64 where it is 16 bytes. The JIT previously emitted 16-byte stores (`STR Qn`) for these types, overwriting adjacent stack memory.
- Fixed `long double` handling on macOS Intel (Darwin). Verified that Apple adheres to the System V ABI for this type: it requires 16-byte stack alignment and returns values on the x87 FPU stack (`ST(0)`).
- Fixed a generic System V ABI bug where 128-bit types (vectors, `__int128`) were not correctly aligned to 16 bytes on the stack relative to the return address, causing data corruption when mixed with odd numbers of 8-byte arguments.
- Fixed the build system (`build.pl`) to better handle external tool failures. Coverage gathering commands (like `codecov`) are now allowed to fail gracefully without breaking the build pipeline.
- Enforced natural alignment for stack arguments in the AAPCS64 implementation. Previously, arguments were packed to 8-byte boundaries, which violated alignment requirements for 128-bit types.
- Fixed a critical deployment issue where the public `infix.h` header included an internal file (`common/compat_c23.h`). The header is now fully self-contained and defines `INFIX_NODISCARD` for attribute compatibility.
- Fixed 128-bit vector truncation on System V x64 (Linux/macOS). Reverse trampolines previously used 64-bit moves (`MOVSD`) for all SSE arguments, corrupting the upper half of vector arguments. They now correctly use `MOVUPS`.
- Fixed vector argument corruption on AArch64. The reverse trampoline generator now correctly identifies vector types and uses 128-bit stores (`STR Qn`) instead of falling back to 64-bit/32-bit stores or GPRs.
- Fixed floating-point corruption on Windows on ARM64. Reverse trampolines now force full 128-bit register saves for all floating-point arguments to ensure robust handling of volatile register states.
- Fixed a logic error in the System V reverse argument classifier where vectors were defaulting to `INTEGER` class, causing the trampoline to look in `RDI`/`RSI` instead of `XMM` registers.
- Fixed Clang coverage reporting by switching from LLVM-specific profiles to standard GCOV formats.
- Fixed potential cache coherency issues on Windows x64. The library now unconditionally calls `FlushInstructionCache` after JIT compilation.
- Hardened the signature parser against integer overflows when parsing array/vector sizes.
- Capped the maximum alignment in `infix_type_create_packed_struct` to 1MB to prevent integer wrap-around bugs in layout calculation.
- Fixed a buffer overread on macOS ARM64 where small signed integers were loaded using 32-bit `LDRSW`. Implemented `LDRSH` and `LDRSB`.
- Updated the `INFIX_NODISCARD` macro logic in `infix.h`. It now prioritizes compiler-specific attributes (like `__attribute__((warn_unused_result))`) over C23 standard attributes on GCC/Clang when not in strict C23 mode. This fixes syntax errors when compiling with C11/C17 standards.
- Fixed `warn_unused_result` warnings across the test suite and fuzzing helpers. Previous tests cast ignored return values to `(void)`, but GCC ignores this cast for functions marked with `warn_unused_result`. All tests now properly check `infix_status` return codes.
- Fixed a "dangling else" warning in `fuzz/fuzz_helpers.c` by adding explicit braces.
- Cleaned up `infix_internals.h` by removing the obsolete declaration for `_infix_forward_create_internal`.
- Made `_infix_forward_create_impl` and `_infix_forward_create_direct_impl` static in `trampoline.c`, as they are only used within that translation unit in the unity build.
- Early attempt to support C++ Itanium (`INFIX_DIALECT_ITANIUM_MANGLING`) and MSVC (`INFIX_DIALECT_MSVC_MANGLING`) mangling in signature stringification. This is mostly for debugging the type system quickly.
  - Supports deeply nested namespaces and scopes (`@Outer::Inner::MyClass`).
  - MSVC mangling correctly handles the reversed-order namespace requirements and special type prefixes (`U` for structs, `T` for unions).
- Added native support for Apple's Hardened Runtime security policy.
  - The JIT engine now utilizes `MAP_JIT` when the `com.apple.security.cs.allow-jit` entitlement is detected.
  - Implemented thread-local permission toggling via `pthread_jit_write_protect_np` to maintain W^X compliance.

## [0.1.3] - 2025-12-19

This release contains real-world usage fixes since I'm using it in Affix.pm and not just experimenting with different JIT forms.

### Changed

- Updated JIT validation logic to explicitly reject incomplete forward declarations, preventing the creation of broken trampolines.

### Fixed

- Fixed a critical file descriptor leak on POSIX platforms (Linux/FreeBSD) where the file descriptor returned by `shm_open` was kept open for the lifetime of the trampoline, eventually hitting the process file descriptor limit (EMFILE). The descriptor is now closed immediately after mapping, as intended.
- Fixed signature positioning cache. The error messages will now (probably) point exactly where things are broken.
- Fixed a critical bug in the Type Registry where forward declarations (e.g., `@Node;`) did not create valid placeholder types, causing subsequent references (e.g., `*@Node`) to fail resolution with `INFIX_CODE_UNRESOLVED_NAMED_TYPE`.
- Fixed `infix_registry_print` to explicitly include forward declarations in the output, improving introspection visibility.
- Updated `is_passed_by_reference` in `abi_win_x64.c` to always return `true` for `INFIX_TYPE_ARRAY`. This ensures the `prepare` stage allocates 8 bytes (pointer size) and the `generate` stage emits a move of the pointer address, not the content.
- Updated `prepare_forward_call_frame_arm64` to treat `INFIX_TYPE_ARRAY` explicitly as a pointer passed in a GPR, bypassing the HFA and aggregate logic.
- Updated `generate_forward_argument_moves_arm64` to handle `INFIX_TYPE_ARRAY` inside the `ARG_LOCATION_GPR` case by using `emit_arm64_mov_reg` to copy the pointer from the scratch register (X9) to the argument register.

## [0.1.2] - 2025-11-26

We'll find out where I go from here.

### Added
- **Direct Marshalling API:** A new, high-performance API (`infix_forward_create_direct`) for language bindings. This allows the JIT compiler to call user-provided marshaller functions directly, bypassing intermediate argument buffers and reducing overhead.
  - Added `infix_forward_create_direct`, `infix_forward_get_direct_code`.
  - Added `infix_direct_arg_handler_t` and `infix_direct_value_t`.
  - See #26.
- Shared Arena Optimization API: Introduced a new set of advanced API functions (`infix_registry_create_in_arena`, `infix_forward_create_in_arena`, etc.) that allow the type registry and trampolines to be created within a user-provided, shared memory arena. When objects share an arena, the library avoids deep-copying named type metadata and instead shares pointers to the canonical types, significantly reducing memory consumption and improving trampoline creation performance for applications with many FFI calls referencing a common set of types.
- Semantic Name Preservation for All Types: The type system can now preserve a semantic name for *any* type defined in a registry, not just structs and unions. An alias like `@MyInt = int32;` or `@MyHandle = *void;` will now produce a type that is structurally identical to its definition but carries the semantic name for introspection.
- New Introspection API: Added `infix_type_get_name(const infix_type* type)` to the public API. This function is now the canonical way to retrieve the semantic alias of any type object, if one exists.
- Added full support for C-style bitfields in structs using the syntax `name : type : width` (e.g., `flags:uint32:3`). The layout engine correctly packs them according to System V rules.
- Added support for C99 Flexible Array Members using the syntax `name : [ ? : type ]`. The layout engine correctly handles their alignment and placement at the end of structs.

### Changed

- Growable Arena: The internal arena for the type registry is no longer fixed-size. Now, it transparently allocates new memory blocks as needed, removing the risk of allocation failures when registering and/or copying a large number of interconnected types.
- Type Registry and Printing Logic: The internals of the type registry and the `infix_type_print` function have been updated to correctly create, copy, and serialize the new `name` field on `infix_type` objects, ensuring that semantic aliases are preserved through all API operations and can be correctly round-tripped to strings.
- Renamed all cookbook examples in `/eg/cookbook`. I can't expect to keep track of recipe numbers with every little idea I decide to throw into the cookbook so I'll just stop trying to count them.
- Windows opens the current executable in `infix_library_open` when the path value is `NULL`.

### Fixed

- Fixed a series of low-level instruction encoding errors in the AVX and AVX-512 instructions leading to `SIGILL` errors when calling functions with `__m256d` or `__m512d` vector types.
- Fixed a critical ABI classification bug on SysV where function parameters of an array type (e.g., `void func(char s[20])`) were incorrectly treated as by-value aggregates. The faulty classification caused `infix` to generate code that passed the array's content on the stack instead of a pointer, leading to stack corruption, crashes, and incorrect argument marshalling.

## [0.1.1] - 2025-11-01

Really sanding down the rough edges this time around. This release includes significant ergonomic improvements to the high-level API.

### Added

- New Signature Keywords: Added keywords for common C and C++ types to improve signature readability and portability.
  - Added `size_t` and `ssize_t` as platform-dependent abstract types.
  - Added `char8_t`, `char16_t`, and `char32_t` as aliases for `uint8`, `uint16`, and `uint32` for better C++ interoperability.
- Cookbook Examples: Extracted all recipes from the cookbook documentation into a comprehensive suite of standalone, compilable example programs located in the `eg/cookbook/` directory.
- Advanced C++ Recipes: Added new, advanced cookbook recipes demonstrating direct, wrapper-free interoperability with core C++ features:
  - Calling C++ virtual functions by emulating v-table dispatch.
  - Bridging C-side stateful callbacks with C++ objects that expect `std::function` or similar callable objects.

### Changed

- Improved C++ Interoperability Recipes: Refined the C++ recipes to focus on direct interaction with C++ ABIs (mangled names, v-tables) rather than relying on C-style wrappers, showcasing more advanced use cases.
- Improved `wchar_t` Guidance: Added a dedicated cookbook recipe explaining the best-practice for handling `wchar_t` and other semantic string types via the Type Registry, ensuring signatures are unambiguous and introspectable.
- Enhanced High-Level API for Registered Types. The primary creation functions (`infix_forward_create`, `infix_forward_create_unbound`, `infix_reverse_create_callback`, and `infix_reverse_create_closure`) can now directly accept a registered named type as a signature.

    ```c
    // The high-level API now understands the "@Name" syntax directly.
    // Assume the registry already has "@Adder_add_fn = (*{ val: int }, int) -> int;"
    infix_reverse_create_callback(&ctx, "@Adder_add_fn", (void*)Adder_add, reg);
    ```

- The `infix_read_global` and `infix_write_global` functions now take an additional `infix_registry_t*` argument to support reading and writing global variables that are defined by a named type (e.g., `@MyStruct`).

### Fixed

- Fixed a critical parsing bug in `infix_register_types` that occurred when defining a function pointer type alias (e.g., `@MyFunc = (...) -> ...;`). The preliminary parser for finding definition boundaries would incorrectly interpret the `>` in the `->` token as a closing delimiter, corrupting its internal nesting level calculation. This resulted in an `INFIX_CODE_UNEXPECTED_TOKEN` error and prevented the registration of function pointer types. The parser is now context-aware and correctly handles the `->` token, allowing for the clean and correct registration of function pointer aliases as intended.

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

[unreleased]: https://github.com/sanko/infix/compare/v0.1.4...HEAD
[0.1.4]: https://github.com/sanko/infix/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/sanko/infix/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/sanko/infix/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/sanko/infix/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/sanko/infix/releases/tag/v0.1.0
