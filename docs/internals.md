# Infix Internals and Architecture

This document provides a deep dive into the architecture and internal workings of `infix`. It is intended for maintainers, contributors, and advanced users who wish to understand the library's design philosophy, core mechanics, security features, and ABI implementations.

## 1. Core Design Philosophy

The architecture of `infix` is the result of a series of deliberate design choices aimed at balancing performance, security, and developer ergonomics.

### 1.1 Guiding Principles

Three high-level principles guide the library's development:

1.  **Security First:** An FFI library with a JIT engine is a prime target for vulnerabilities. We proactively defend against these with a multi-layered approach: strict W^X memory, hardened integer arithmetic, guard pages for freed code, and read-only callback contexts. All complex components are subjected to continuous fuzz testing.
2.  **Performance by Design:** FFI overhead must be minimal. The API is intentionally designed to separate the expensive, one-time **generation cost** from the near-zero **call-time cost**. This encourages users to cache trampolines, making the FFI overhead negligible in high-performance applications.
3.  **Abstraction and Portability:** Platform- and ABI-specific logic is strictly isolated behind a clean internal interface (the "ABI spec" v-tables). This allows the core trampoline engine to remain platform-agnostic, which dramatically simplifies maintenance and makes porting to new architectures a clear, well-defined process.

### 1.2 Key Architectural Decisions

#### The Unity Build
`infix` is designed to be built as a single translation unit. The top-level `src/infix.c` file simply `#include`s all other core `.c` files.
*   **Rationale**:
    1.  **Simplicity of Integration:** A user can add `src/infix.c` and the `include` directory to their project, and it will build without complex makefiles.
    2.  **Potential for Optimization:** Compiling the entire library as a single unit gives the compiler maximum visibility, enabling more aggressive inlining and interprocedural optimizations.
    3.  **Encapsulation:** Because most functions are declared `static`, we avoid polluting the global namespace. The `trampoline.c` file is key, as it includes the ABI-specific `.c` files directly, ensuring their internal functions remain private.

#### The Self-Contained Object Model
Both `infix_forward_t` and `infix_reverse_t` are designed as **self-contained objects**. When a trampoline is created, it performs a **deep copy** of all the `infix_type` metadata it needs into its own private, internal memory arena.
*   **Rationale:** This prioritizes memory safety and API simplicity. It completely eliminates a class of use-after-free bugs where a user might destroy an arena used for type creation while a trampoline still points to it. It also enables a safe introspection API, as the type information is guaranteed to be valid for the entire lifetime of the trampoline handle.

#### Arena-Based Manual API
The low-level, "manual" API for creating `infix_type` objects is **exclusively arena-based**.
*   **Rationale:** The old rule—"the library takes ownership on success, the caller owns on failure"—is a notorious source of memory leaks. By forcing the use of an arena, we eliminate this entire class of bugs. The user's responsibility is simplified to a single pattern: create an arena, perform all type creations, and destroy the arena once.

#### Universal Context for Callbacks
All user-provided C callback handlers **always** receive a pointer to their `infix_context_t` as their first argument.
*   **Rationale:** This prioritizes power and API simplicity. It allows every callback to be stateful, which is essential for adapting to C libraries that don't provide a `void* user_data` parameter. A stateless handler can simply ignore the context. This consistent pattern is safer and easier to learn than offering multiple callback modes.

---

## 2. Architectural Overview

The library can be broken down into five main layers:

1.  **Public API Layer (`infix.h`, `signature.c`, `registry.c`)**: The user-facing interface, providing both a high-level Signature API and a low-level Manual API.
2.  **Type System (`types.c`)**: Describes the data types used in function signatures.
3.  **Trampoline Engine (`trampoline.c`)**: The core, ABI-agnostic orchestrator that uses the other layers to build the final machine code.
4.  **ABI Abstraction Layer (`infix_internals.h`, `arch/...`)**: Defines the v-table interfaces (`infix_..._abi_spec`) and provides the concrete, platform-specific implementations.
5.  **OS Abstraction Layer (`executor.c`)**: Handles the allocation and protection of memory for JIT-compiled code.

### The Trampoline Generation Pipeline

The process of creating a trampoline, from signature to executable code, follows a clear pipeline:

1.  **Parsing:** `infix_forward_create` receives a signature string. It calls the signature parser, which builds a temporary graph of `infix_type` objects in an arena. This graph may contain unresolved `@Name` placeholders.
2.  **Resolution:** If a registry was provided, the **resolver** (`_infix_resolve_type_graph`) walks the temporary type graph, looking up each `@Name` and replacing the placeholder with a pointer to the fully defined type from the registry.
3.  **Layout Calculation:** The resolved type graph is passed to the Trampoline Engine. The engine selects the correct ABI spec and calls its `prepare_*_call_frame` function. This is the "brain" of the ABI; it classifies every argument and produces a `..._call_frame_layout` blueprint.
4.  **Code Generation:** The engine calls the ABI spec's code generation functions (`generate_*_prologue`, etc.) in sequence. Each function appends platform-specific machine code to a `code_buffer`.
5.  **Memory Finalization:** The generated code is copied to a new page of executable memory, which is then made non-writable (enforcing W^X).
6.  **Handle Creation:** A final `infix_forward_t` handle is allocated, containing its own private arena into which a deep copy of the type graph is made. This makes the handle a safe, self-contained object.

```mermaid
graph TD
    subgraph "Setup Phase (in infix_forward_create)"
        A[User calls API with Signature String] --> B(Parse Signature & Resolve Names);
        B --> C[Get ABI Spec V-Table];
        C --> D{prepare_forward_call_frame};
        D --> E[Generate Machine Code into Buffer];
        E --> F[Allocate & Finalize Executable Memory];
        F --> G[Deep Copy Types into Handle];
        G --> H[Return Trampoline Handle];
    end

    subgraph "Call Phase (user calls trampoline)"
        I[cif_func(...)] --> J(Prologue: Set up stack);
        J --> K(Argument Marshalling);
        K --> L[call native_func];
        L --> M(Epilogue: Handle return, restore stack);
        M --> N[Return to User];
    end
```

---

## 3. Security Features Deep Dive

### 3.1 Write XOR Execute (W^X)

A memory region is never simultaneously writable and executable. The implementation strategy varies by platform for maximum security and compatibility:

```mermaid
---
config:
  theme: dark
---
graph TD
    subgraph "Windows/macOS/etc. (Single-Mapping)"
        A[VirtualAlloc / mmap<br>PROT_READ | PROT_WRITE] --> B[Write JIT Code];
        B --> C[VirtualProtect / mprotect<br>PROT_READ | PROT_EXEC];
        C --> D(Return RX Pointer);
    end
    subgraph "Linux/BSD (Dual-Mapping)"
        E[shm_open_anonymous] --> F[mmap RW view];
        E --> G[mmap RX view];
        F --> H[Write JIT Code];
        G --> I(Return RX Pointer);
        H --> I;
    end
```

### 3.2 Guard Pages and Read-Only Contexts
To mitigate use-after-free bugs, `infix_executable_free` turns freed memory into a non-accessible "guard page," causing an immediate and safe crash on attempted use. Additionally, after a reverse trampoline's context is created, its memory is made read-only to prevent runtime corruption.

### 3.3 Fuzz Testing
The entire `infix` API surface, especially the signature parser and ABI classifiers, is continuously tested using `libFuzzer` and `AFL++`. The fuzzing harnesses (`fuzz/`) are designed to find memory safety violations (ASan), integer overflows (UBSan), and infinite loops (timeouts). All findings are converted into permanent regression tests.

---

## 4. ABI Internals

This section provides a low-level comparison of the ABIs supported by `infix`.

| Feature                      | System V AMD64 (Linux, macOS)                                   | Windows x64                                                    | AArch64 (ARM64)                                                 |
| ---------------------------- | --------------------------------------------------------------- | -------------------------------------------------------------- | --------------------------------------------------------------- |
| **Integer/Pointer Args**     | 6 GPRs: `RDI, RSI, RDX, RCX, R8, R9`                            | 4 GPRs: `RCX, RDX, R8, R9` (Shared slots)                      | 8 GPRs: `X0` - `X7`                                             |
| **Floating-Point Args**      | 8 XMMs: `XMM0` - `XMM7` (Separate pool)                         | 4 XMMs: `XMM0` - `XMM3` (Shared slots)                         | 8 VPRs: `V0` - `V7` (Separate pool)                             |
| **Struct/Union Passing**     | **Recursive Classification**. Passed in GPRs, XMMs, or both.    | **By Reference** if size is not 1, 2, 4, or 8 bytes.             | **By Reference** if size > 16 bytes. HFAs passed in VPRs.       |
| **Return by Hidden Pointer** | If struct > 16 bytes or classified as MEMORY. Pointer in `RDI`. | If struct size is not 1, 2, 4, or 8. Pointer in `RCX`.         | If struct > 16 bytes. Pointer in `X8`.                          |
| **Return Value Registers**   | `RAX` (int), `RAX:RDX` (int pair), `XMM0` (float), `st(0)` (ld) | `RAX` (int/struct), `XMM0` (float)                             | `X0` (int), `X0:X1` (int pair), `V0` (float/HFA)                |
| **Variadic `printf` Rule**   | `AL` must contain the number of XMM registers used.             | Floating-point variadic args are passed in GPRs *and* XMMs.    | Standard: no special rule. Apple: All variadic args on stack.   |
| **Stack Alignment**          | 16-byte boundary before `call`.                                 | 16-byte boundary before `call`.                                | 16-byte boundary.                                               |
| **Shadow Space**             | No. Has a 128-byte "red zone" below `RSP`.                      | Yes, caller allocates 32 bytes on stack for the callee.        | No.                                                             |

---

## 5. Maintainer's Debugging Guide

### Method 1: Static Analysis with `infix_dump_hex`
The simplest way to see what the JIT is producing is to enable `INFIX_DEBUG_ENABLED=1` in your build. This will trigger a hexdump of the generated machine code after every trampoline creation.

```
# My Forward Trampoline (size: 78 bytes)
#   0x0000: 55 48 89 e5 41 54 41 55  41 56 41 57 49 89 cc 49 | UH..ATAUAVAWI..I
#   0x0010: 89 d5 4d 89 c6 48 81 ec  20 00 00 00 4c 89 e9 4d | ..M..H.. ...L..M
#   ...
```

### Method 2: Live Debugging with GDB/LLDB
This is the most powerful method. It allows you to step through the JIT'd code one instruction at a time.

1.  **Get the Address**: In your test code, print the address of the executable pointer right after it's generated.
    ```c
    infix_cif_func cif_func = infix_forward_get_code(trampoline);
    printf("DEBUG: Trampoline generated at address: %p\n", (void*)cif_func);
    ```
2.  **Run Under Debugger**: `gdb ./my_test_executable`
3.  **Set Breakpoint**: Use the printed address to set a breakpoint: `(gdb) b *0x7ffff7fde000`
4.  **Trigger and Disassemble**: Run the program. When it breaks, use `disassemble` to view the JIT code.
5.  **Step and Verify**: Use `stepi` (step instruction) and `info registers` to walk through the code and check register values.

### Useful Tools
* **Online Assembler/Disassembler**: [shell-storm.org](https://shell-storm.org/online/Online-Assembler-and-Disassembler/) is an invaluable tool for quickly checking instruction encodings.

## External ABI Documentation

*   **System V AMD64 ABI:** [https://github.com/hjl-tools/x86-psABI/wiki/x86-64-psABI-1.0.pdf](https://github.com/hjl-tools/x86-psABI/wiki/x86-64-psABI-1.0.pdf)
*   **Microsoft Windows x64 ABI:** [https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention](https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention)
*   **ARM 64-bit (AArch64) ABI:** [https://developer.arm.com/documentation/ihi0055/latest/](https://developer.arm.com/documentation/ihi0055/latest/)
*   **Apple ARM64 Specifics:** [https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms](https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms)

This isn't documentation but I couldn't have come close to getting infix off the ground without https://shell-storm.org/online/Online-Assembler-and-Disassembler/
