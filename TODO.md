# **Project Roadmap: infix FFI**

This document outlines the planned development goals for the infix FFI library, categorized by priority. Each item includes the context for why it's important, the proposed idea, a clear definition of what "done" looks like, and potential challenges.

## **High Priority: Foundation & Stability**

*These tasks focus on critical infrastructure, core reliability, and essential C language feature completeness. They must be addressed before major new features are added.*

- [x] **Refactor Platform-Specific Emitters**
    *   **Context:** The initial design mixed platform-specific instruction emitters (e.g., for x86-64) into the generic `trampoline.c` and public `infix.h`, breaking the library's architectural abstraction.
    *   **Idea:** Move all platform-specific emitter functions into their own dedicated, internal modules (e.g., `abi_x64_emitters.c`, `abi_arm64_emitters.c`) with non-public headers.
    *   **Goal:** The generic `trampoline.c` is now 100% platform-agnostic. The public `infix.h` no longer exposes any internal emitter functions. The architecture is cleaner, more maintainable, and easier to extend to new platforms.

- [x] **Implement Fuzzing**
    *   **Context:** The type creation API is a potential attack surface for security vulnerabilities via malformed input. Fuzzing is the most effective method for automatically discovering such bugs.
    *   **Idea:** Create a fuzzing harness using a framework like libFuzzer that calls the type creation APIs with random, malformed data.
    *   **Goal:** An `xmake fuzz` target is created. The CI pipeline runs the fuzzer for a set duration to continuously search for vulnerabilities. The fuzzer runs without finding any crashes.
    *   **Possible Roadblocks:** Fuzzing can be slow; requires careful tuning of the CI process to avoid excessive run times. Setting up the fuzzing environment can be complex.

- [x] **Add Memory Stress Test with Valgrind Monitoring**
    *   **Context:** In a C library that performs many dynamic allocations, it's easy to introduce subtle memory leaks.
    *   **Idea:** Create a new test that rapidly creates and destroys thousands of trampolines with varied signatures in a tight loop.
    *   **Goal:** A new test target, `xmake run memory_test`, is created. The CI pipeline runs this test under Valgrind's `memcheck` tool on the Linux runner with `--leak-check=full`. The build must fail if Valgrind reports *any* memory leaks.
    *   **Possible Roadblocks:** Test can be slow to run; requires a Linux-based CI runner with Valgrind installed.

- [x] **Add Threading Stress Test**
    *   **Context:** The documentation claims callbacks are thread-safe. This must be rigorously proven to detect potential race conditions.
    *   **Idea:** Create a test that spawns multiple threads to call a single reverse trampoline concurrently.
    *   **Goal:** The project is compiled with a thread sanitizer (`-fsanitize=thread` for GCC/Clang) in the CI, and the stress test must pass without any reported data races.
    *   **Possible Roadblocks:** Threading bugs can be notoriously difficult to reproduce reliably; requires a sanitizer-compatible toolchain.

- [x] **Use Guard Pages for Freed Trampolines**
    *   **Context:** After a trampoline is freed, its function pointer becomes a dangling pointer. If a user accidentally calls it, a use-after-free vulnerability can be triggered.
    *   **Idea:** Instead of just releasing memory, change its protection to `PROT_NONE` (no read/write/execute). This turns a subtle vulnerability into a safe, immediate, and obvious crash.
    *   **Goal:** The `infix_executable_free` function is updated to use `mprotect`/`VirtualProtect`. A new test is created that frees a trampoline and then calls its old function pointer, asserting that the program safely terminates.
    *   **Possible Roadblocks:** Testing for an expected crash is non-trivial and may require platform-specific signal handling or process management in the test suite.

- [x] **Add `long double` Support**
    *   **Context:** `long double` was the last major C primitive type not supported by the library.
    *   **Idea:** Add a new primitive type and implement the correct, platform-specific ABI handling for it.
    *   **Goal:** `long double` is a recognized `infix_type` and passes correctly in forward and reverse calls on all supported platforms (System V, Windows/GCC, AArch64).

- [x] **Read-Only Callback Contexts (RELRO for Callbacks)**
    *   **Context:** The `infix_reverse_t` struct contains function pointers that could be targeted by memory corruption attacks to hijack control flow.
    *   **Idea:** After a callback context is created, use `mprotect`/`VirtualProtect` on the memory page containing it to make it read-only.
    *   **Goal:** The context is hardened by default. Any attempt to write to a hardened context struct will cause an immediate segmentation fault, preventing the attack.
    *   **Possible Roadblocks:** `mprotect` operates on page boundaries, not on individual structs. This requires careful memory management to ensure unrelated writable data is not on the same page, which might make the implementation complex.

## **Medium Priority: Expansion & Optimization**

*Once the foundation is solid, these tasks focus on adding major new capabilities, improving performance, and expanding test coverage.*

- [x] **Internal Arena Allocator**
    *   **Context:** The JIT generation process involves many small, short-lived memory allocations which can be inefficient and cause fragmentation.
    *   **Idea:** Implement a simple arena/pool allocator for the lifetime of a single trampoline generation to reduce `malloc` overhead.
    *   **Goal:** This is an internal optimization. A benchmark must show a measurable speedup in the trampoline generation phase (the one-time setup cost). Trampoline generation is now ~50x faster for complex signatures.
    *   **Possible Roadblocks:** Requires careful changes to internal APIs to pass the allocator context around; potential for subtle memory management bugs during implementation.

- [x] **Profile Code Generation and Execution**
    *   **Context:** Before optimizing, we need to identify performance bottlenecks. We need to measure both the one-time cost of generating a trampoline and the per-call overhead of executing it.
    *   **Idea:** Use platform-specific profiling tools (Valgrind/Callgrind, Instruments, VTune) to measure trampoline generation and execution overhead.
    *   **Goal:** A new document, `docs/performance.md`, is created to summarize the findings and guide future optimization work.
    *   **Possible Roadblocks:** Profiling JIT'd code can be complex, as symbols may not be easily visible in standard profilers.

- [x] **Implement Packed Argument Trampolines**
    *   **Context:** The current `void** args` API requires pointer indirection. A "packed" API would improve cache performance by passing arguments in a single contiguous block of memory.
    *   **Idea:** Implement `infix_forward_create_packed`, where the JIT'd code reads arguments from offsets relative to a single pointer.
    *   **Goal:** A benchmark demonstrates a significant performance improvement for calls with many arguments compared to the standard trampoline.

## **Low Priority: Advanced Features & Polish**

*These items are valuable but less critical. They can be addressed over time to round out the library's feature set.*

- [ ] **Implement RISC-V 64-bit ABI**
    *   **Context:** RISC-V is a growing open-source architecture. Adding support would demonstrate the library's portability.
    *   **Idea:** Create a new `abi_riscv.c` file and associated low-level instruction emitters, following the roadmap in `internals.md`.
    *   **Goal:** The library successfully compiles and passes the entire test suite on a RISC-V 64-bit platform (e.g., in QEMU within the CI).
    *   **Possible Roadblocks:** Access to RISC-V hardware or a reliable CI-based emulator is required for testing.

- [ ] **(Re-scoped) Enhance `symbol_finder.pl` with Multi-Language Demangling**
    *   **Context:** The `symbol_finder.pl` script can be extended to demangle symbols from C++, Rust, and Fortran, making it a powerful tool for FFI development.
    *   **Idea:** Adopt a pragmatic, phased approach to implementation.
    *   **Goal:**
        *   **Phase 1:** The script shells out to standard toolchains (`c++filt` for Itanium) for immediate functionality.
        *   **Phase 2:** Begin the major task of writing pure-Perl demanglers from scratch for Itanium C++ and Rust v0 to remove all external tool dependencies.
    *   **Possible Roadblocks:** Writing full-featured demanglers from scratch (Phase 2) is an extremely large and complex undertaking.

- [ ] **Direct System Call Interface**
    *   **Context:** Some advanced applications need to bypass standard C libraries and make direct calls to the OS kernel, which uses a different, low-level ABI.
    *   **Idea:** Create a new `infix_syscall_create` API that emits assembly to load registers and execute the `syscall` instruction.
    *   **Goal:** A user can successfully call a basic OS syscall, such as `write` on Linux, using a generated trampoline.
    *   **Possible Roadblocks:** Extremely high implementation cost. Requires a unique ABI implementation for every supported OS. Testing is very difficult and OS-specific.

- [ ] **Add Exception Handling Boundary**
    *   **Context:** An unhandled C++ or SEH exception that crosses the FFI boundary will crash the program. A robust library should provide a way to handle this.
    *   **Idea:** Create a `infix_forward_create_safe` function where the JIT code wraps the native call in a `try...catch` or `__try...__except` block.
    *   **Goal:** If a native function throws an exception, the trampoline catches it, returns `INFIX_ERROR_NATIVE_EXCEPTION`, and the program does not crash.
    *   **Possible Roadblocks:** This requires mixing C and C++ or using platform-specific SEH, which adds significant complexity and potential portability issues.

- [ ] **Add Bitfield Support in Structs**
    *   **Context:** C allows structs to have bitfields, but their memory layout is highly compiler-specific. Supporting them is an advanced FFI feature.
    *   **Idea:** Extend the `infix_type` system to describe bitfields and implement the packing/unpacking logic for each ABI.
    *   **Goal:** Successfully call a function that takes a struct containing bitfields and get the correct result.
    *   **Possible Roadblocks:** This is a notoriously difficult part of FFI implementation, as bitfield layout rules are often poorly documented and vary even between versions of the same compiler.

- [ ] **Add Type System Builder API**
    *   **Context:** The current Manual API for creating complex structs is verbose and requires manual memory management for the member array within the arena.
    *   **Idea:** Create a fluent builder pattern API (e.g., `infix_struct_builder_*` functions) to simplify type creation.
    *   **Goal:** A user can define a complex struct without manually allocating or managing the `infix_struct_member` array, reducing boilerplate and potential for errors.

- [ ] **Add Support for 32-bit Architectures**
    *   **Context:** A major future direction to support legacy or embedded systems.
    *   **Idea:** Create new ABI backends for 32-bit x86 and ARM.
    *   **Goal:** The library compiles and passes the test suite when targeting a 32-bit architecture.
    *   **Possible Roadblocks:** This is a very large undertaking, effectively doubling the number of supported ABIs that must be maintained and tested.

- [ ] **Decouple Debug Logging from `double_tap.h`**
    *   **Context:** The library's internal `INFIX_DEBUG_PRINTF` macro should not be tied to the test framework's `note()` function, which improves modularity.
    *   **Idea:** Refactor `INFIX_DEBUG_PRINTF` in `utility.h` to use `fprintf(stderr, ...)` directly.
    *   **Goal:** The library source code (`src/`) has no includes of `double_tap.h`. Internal debug messages are printed to `stderr` when `INFIX_DEBUG_ENABLED` is active.
    *   **Possible Roadblocks:** Minimal; this is a straightforward refactoring task.

- [x] **Investigate and Fix Read-Only Context on macOS**
    *   **Context:** The read-only hardening for reverse trampoline contexts does not currently work on macOS due to platform-specific memory protection behavior.
    *   **Idea:** Research the correct combination of `mmap` flags and/or other system calls required to create a reliably read-only data page on macOS.
    *   **Goal:** The "Writing to a hardened reverse trampoline context causes a crash" test passes successfully on macOS.
    *   **Possible Roadblocks:** This may require deep knowledge of macOS virtual memory and could be more complex than on other POSIX systems.

- [ ] **Add Support for Advanced C Types (`_Complex` and SIMD)**
    *   **Context:** Modern C and its common extensions include types for complex numbers (`float _Complex`, `double _Complex`) and SIMD vectors (`__m128`, NEON types) that have specific ABI passing rules. Supporting them directly would improve interoperability with scientific and multimedia libraries.
    *   **Idea:** Extend the `infix_type` system with new categories or primitives for these types. Implement the corresponding ABI classification and marshalling logic in each backend. For example, `_Complex` types are often passed as if they were a two-element struct of floats/doubles.
    *   **Goal:** A user can create an `infix_type` for `double _Complex` and successfully call a function that uses it, with the library handling the ABI rules correctly on all supported platforms.
    *   **Possible Roadblocks:** SIMD types in particular have very platform-specific ABI rules that will require careful research for each backend.
