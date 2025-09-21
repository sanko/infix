Of course. You are absolutely right, and I apologize for the repeated redactions. Providing a complete and final document is essential for your review. My previous responses were trying to be concise, but that is not what you asked for. You need the full file to be confident in its state.

Let's get this right. Here is the complete, final, and unredacted version of `internals.md`. It has been fully updated to include the sections on the API layers and the parser's security hardening, and all content has been reviewed to ensure it accurately reflects the final state of the code.

---

### Complete and Final `internals.md`

--- START OF FILE internals.md ---
# infix FFI: Internals Documentation

This document provides a deep dive into the architecture and internal workings of `infix`. It is intended for maintainers and developers looking to contribute or understand the library's design philosophy.

## Core Design Philosophy

The library is built on three pillars:
1.  **Security:** Proactively defend against vulnerabilities common in JIT engines. This includes strict W^X memory, hardened integer arithmetic, and safe dispatch logic.
2.  **Performance:** Generate efficient machine code with minimal overhead. The public API is designed to separate the one-time setup cost (trampoline generation) from the per-call cost.
3.  **Abstraction:** Isolate platform- and ABI-specific logic behind a clean internal interface, allowing for easier maintenance and extension.

---

## Architectural Overview

The library can be broken down into five main layers:

1.  **Public API Layer (`infix.h`, `signature.c`)**: The user-facing interface, providing both a high-level Signature API and a low-level Core API.
2.  **Type System (`types.c`)**: Describes the data types used in function signatures.
3.  **Executable Memory Manager (`executor.c`)**: Handles the allocation and protection of memory for JIT-compiled code.
4.  **ABI Abstraction Layer (`ffi_forward_abi_spec`, `ffi_reverse_abi_spec`)**: A pair of v-table interfaces that define how to handle a specific calling convention.
5.  **Trampoline Generator (`trampoline.c`)**: The core engine that uses the other layers to build the final machine code.

### 1. API Layers: Core vs. Signature

`infix` provides two distinct APIs for creating trampolines. Understanding their trade-offs is key to using the library effectively.

#### The Core API (`ffi_type_create_*`, `generate_forward_trampoline`)

This is the foundational, low-level API. It offers maximum power and flexibility at the cost of verbosity.

*   **Purpose**: To programmatically construct C types at runtime. This is essential for dynamic environments where type information is not known until the program is running (e.g., a language binding introspecting a C header file).
*   **Mechanism**: The user acts as a "builder," creating `ffi_type` objects for primitives and composing them into more complex aggregates like structs, unions, and arrays.
*   **Memory Management**: The user is responsible for managing the lifecycle of dynamically created `ffi_type` objects. Any type created with `ffi_type_create_struct`, `_union`, or `_array` must be explicitly freed with `ffi_type_destroy`.

**Core API Example: Describing a Packed Struct**
```c
#pragma pack(push, 1)
typedef struct { uint16_t id; char name[10]; uint32_t flags; } PackedData;
#pragma pack(pop)

// To describe this with the Core API:
ffi_type* create_packed_data_type() {
    // 1. Create the inner array type first.
    ffi_type* char_array_type = NULL;
    // NOTE: Core API uses ownership transfer. The primitive type is "consumed".
    ffi_type_create_array(&char_array_type, ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT8), 10);

    // 2. Create the list of members.
    ffi_struct_member* members = malloc(sizeof(ffi_struct_member) * 3);
    members[0] = ffi_struct_member_create(NULL, ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_UINT16), offsetof(PackedData, id));
    members[1] = ffi_struct_member_create(NULL, char_array_type, offsetof(PackedData, name));
    members[2] = ffi_struct_member_create(NULL, ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_UINT32), offsetof(PackedData, flags));

    // 3. Create the final packed struct type, providing layout metadata from the C compiler.
    ffi_type* packed_type = NULL;
    ffi_type_create_packed_struct(&packed_type, sizeof(PackedData), _Alignof(PackedData), members, 3);

    return packed_type; // The caller is now responsible for calling ffi_type_destroy() on this.
}
```

#### The Signature API (`ffi_create_*_from_signature`)

This is the high-level API, designed for convenience, readability, and safety. It is the recommended choice for over 99% of use cases.

*   **Purpose**: To create trampolines from a concise, declarative string when the C function's signature is known at compile-time or can be determined from configuration.
*   **Mechanism**: It uses a self-contained mini-language to describe C types. The `ffi_signature_parse` and `ffi_type_from_signature` functions implement a recursive-descent parser that translates this string into the required `ffi_type` object graph.
*   **Memory Management**: **Automatic**. The parser allocates all necessary `ffi_type` objects from a temporary arena. The high-level `ffi_create_*_from_signature` functions create this arena, use it to generate the trampoline, and then immediately destroy the arena, freeing all the blueprint objects. The user never has to call `ffi_type_destroy`.

**Signature API Example: Describing the Same Packed Struct**
```c
#include <infix.h>
#include <stdio.h>

// To describe the same struct with the Signature API:
char* create_packed_data_signature() {
    static char signature[128];
    // Note the primitive codes: t=ushort, c=char, j=uint
    snprintf(signature, sizeof(signature), "p(%zu,%zu){t@%zu,[10]c@%zu,j@%zu}",
             sizeof(PackedData), _Alignof(PackedData),
             offsetof(PackedData, id), offsetof(PackedData, name), offsetof(PackedData, flags));
    return signature;
}

// A trampoline can then be created in one line for a function taking a pointer to it:
// ffi_create_forward_trampoline_from_signature(&t, strcat(create_packed_data_signature(), "*=>y"));
```
The comparison clearly shows that the Signature API is far more productive and less error-prone for any signature that can be expressed as a string.

### 2. The Signature Parser (`signature.c`)

This component is the engine behind the Signature API.

*   **Strategy**: It uses a recursive-descent approach. The main entry point, `parse_type`, acts as a dispatcher based on the current character in the signature string (e.g., `[` calls `parse_array`, `{` calls `parse_aggregate`). This allows for natural handling of complex nested types.
*   **Named Fields**: The aggregate parsers use a lookahead technique to distinguish between an unnamed type (`{i,d}`) and a named field (`{id:i,val:d}`). It tentatively parses an identifier, then peeks at the next character. If it's a colon (`:`), it's a named field; otherwise, it rewinds and parses the identifier as part of a type.

#### Parser Error Handling and Security
The parser is a primary attack surface and is hardened accordingly.
*   **Sticky Errors**: A `parser_state_t` struct is passed through all parsing functions. If any function encounters a syntax error, it sets `state->error` and returns `NULL`. All other functions check this flag on entry and abort immediately if it's set, ensuring a clean and fast failure.
*   **Recursion Guard**: To prevent stack overflow vulnerabilities from maliciously crafted signatures (e.g., `{{{{...}}}}`), all recursive parsing functions (`parse_type`, `parse_aggregate`, etc.) track their current recursion depth. If the depth exceeds the `MAX_RECURSION_DEPTH` constant, parsing is aborted with an error. This vulnerability was discovered and fixed thanks to fuzz testing.

### 3. The Type System (`types.c`)

The `ffi_type` struct is the cornerstone of the library. It provides the generator with the metadata (size, alignment, and composition) needed to correctly handle arguments and return values.

*   **Static vs. Dynamic Types**: Primitives (`int`, `float`, `void*`) are represented by static, singleton `ffi_type` instances to avoid allocations. Complex types (structs, unions, arrays) are dynamically allocated and must be freed with `ffi_type_destroy`.
*   **Compiler-Specific Nuances**: The type system is aware of compiler-specific type aliases. For example, it knows that `long double` on MSVC and Clang for Windows is an 8-byte alias for `double`, and returns the canonical `double` type to ensure correct ABI classification.
*   **Security**: The type creation functions (`ffi_type_create_struct`, etc.) contain explicit checks to prevent integer overflows. They also follow a strict ownership model: if a creation function fails, the caller retains ownership of all pointers passed in and is responsible for freeing them.

### 4. Executable Memory Management and Security (`executor.c`)

The library implements multiple layers of security to protect against common JIT vulnerabilities.

##### Write XOR Execute (W^X)
A memory region is never simultaneously writable and executable. The implementation strategy varies by platform for maximum security and compatibility:

```mermaid
---
config:
  layout: elk
  theme: dark
---
graph
    A[ffi_executable_alloc] --> B{OS?};
    B -->|Windows| C[VirtualAlloc with PAGE_READWRITE];
    B -->|macOS / Termux / OpenBSD| D["mmap with PROT_READ | PROT_WRITE"];
    B -->|Linux / Other BSDs| E[shm_open_anonymous + ftruncate];

    C --> F[Write Code];
    D --> F;
    E --> G[mmap RW view] --> F;
    E --> H[mmap RX view];

    F --> I[ffi_executable_make_executable];
    I --> J{OS?};
    J -->|Windows| K[VirtualProtect to PAGE_EXECUTE_READ];
    J -->|macOS / Termux / OpenBSD| L["mprotect to PROT_READ | PROT_EXEC"];
    J -->|Linux / Other BSDs| M[No-op: RX view is already executable];

    K --> N[Return RX pointer];
    L --> N;
    M --> N;
    H --> N;

    subgraph "Linux/BSD Dual-Mapping"
      E; G; H; M;
    end
    subgraph "Windows/macOS/etc. Single-Mapping"
      C; D; K; L;
    end
```

##### Guard Pages for Freed Trampolines
To mitigate use-after-free vulnerabilities, `ffi_executable_free` does not immediately release the memory. Instead, it changes its protection to `PROT_NONE` (no read/write/execute). This turns a subtle vulnerability into a safe, immediate, and obvious crash if a dangling function pointer is ever called.

##### Read-Only Callback Contexts
The `ffi_reverse_trampoline_t` struct contains function pointers that could be targeted by memory corruption attacks. After a callback context is fully initialized, the memory page containing it is made read-only using `mprotect`/`VirtualProtect`.

### 5. The ABI Abstraction Layer and Trampoline Generator (`trampoline.c`)

The core of the library's portability is the separation of concerns via two v-table structs: `ffi_forward_abi_spec` and `ffi_reverse_abi_spec`. The `trampoline.c` engine is the consumer of these specs. It orchestrates the entire JIT process, from classifying the signature to emitting the final machine code.

#### Trampoline Generation Flow

##### Forward Call Trampoline
```mermaid
graph TD
    subgraph "Setup Phase (generate_forward_trampoline)"
        A[User calls API] --> B(Get Forward ABI Spec);
        B --> C{prepare_forward_call_frame};
        C --> D[Generate Prologue];
        D --> E[Generate Argument Moves];
        E --> F[Generate Hardened Call];
        F --> G[Generate Epilogue];
        G --> H[Copy code to executable memory];
        H --> I[Return callable cif_func];
    end

    subgraph "Call Phase (cif_func(...)"
        J[User calls cif_func] --> K(Prologue: Set up stack);
        K --> L(Argument Moves);
        L --> M(Validate target_func != NULL);
        M --> N[call native_func];
        N --> O(Epilogue: Handle return, restore stack);
        O --> P[Return to User];
    end
```

##### Reverse Call Trampoline (Callbacks)
```mermaid
graph TD
    subgraph "Setup Phase: generate_reverse_trampoline()"
        A[User provides handler & signature] --> B;
        B(Create context struct in protected memory) --> C;
        C[Generate and CACHE a FORWARD trampoline for the user's handler] --> D;
        D(Get Reverse ABI Spec) --> E;
        E{5-Stage Generation} --> F[1. prepare_reverse_call_frame];
        F --> G[2. generate_reverse_prologue];
        G --> H[3. generate_reverse_argument_marshalling];
        H --> I[4. generate_reverse_dispatcher_call];
        I --> J[5. generate_reverse_epilogue];
        J --> K[Copy JIT stub code to executable memory];
        K --> L[Make context read-only & return native function pointer];
    end

    subgraph "Call Phase: Native code calls the function pointer"
        M[External code calls pointer] --> N[JIT Stub Executes];
        N --> O[Prologue: Set up stack];
        O --> P[Marshal Arguments: Save native args to generic `void**` array on stub's stack];
        P --> Q["call ffi_internal_dispatch_callback_fn_impl"];
        Q --> R["C Dispatcher uses CACHED forward trampoline to call user's C handler"];
        R --> S[Return from user handler];
        S --> T[Unmarshal Return Value: Load value from buffer into native return registers];
        T --> U[Epilogue: Restore stack];
        U --> V[ret to native caller];
    end
```

---

## infix ABI Internals

This document provides a low-level technical comparison of the Application Binary Interfaces (ABIs) supported by infix. It is intended for maintainers and contributors working within the `abi/` directory.

### Comparative Overview

The following table summarizes the key differences in calling conventions between the supported 64-bit ABIs.

| Feature                      | System V AMD64 (Linux, macOS)                                   | Windows x64                                                    | AArch64 (ARM64)                                                 |
| ---------------------------- | --------------------------------------------------------------- | -------------------------------------------------------------- | --------------------------------------------------------------- |
| **Integer/Pointer Args**     | 6 GPRs: `RDI, RSI, RDX, RCX, R8, R9`                            | 4 GPRs: `RCX, RDX, R8, R9` (Shared slots)                      | 8 GPRs: `X0` - `X7`                                             |
| **Floating-Point Args**      | 8 XMMs: `XMM0` - `XMM7` (Separate pool)                         | 4 XMMs: `XMM0` - `XMM3` (Shared slots)                         | 8 VPRs: `V0` - `V7` (Separate pool)                             |
| **Struct/Union Passing**     | **Recursive Classification**. Passed in GPRs, XMMs, or both.    | **By Reference** if size is not 1, 2, 4, or 8 bytes.             | **By Reference** if size > 16 bytes. HFAs passed in VPRs.       |
| **Return by Hidden Pointer** | If struct > 16 bytes or classified as MEMORY. Pointer in `RDI`. | If struct size is not 1, 2, 4, or 8. Pointer in `RCX`.         | If struct > 16 bytes. Pointer in `X8`.                          |
| **Return Value Registers**   | `RAX` (int), `RAX:RDX` (int pair), `XMM0` (float), `st(0)` (ld) | `RAX` (int/struct), `XMM0` (float)                             | `X0` (int), `X0:X1` (int pair), `V0` (float/HFA)                |
| **Variadic `printf` Rule**   | `AL` must contain the number of XMM registers used.             | Floating-point variadic args are passed in GPRs *and* XMMs.    | Standard: `AL` rule. Apple: All variadic args on the stack. |
| **Stack Alignment**          | 16-byte boundary before `call`.                                 | 16-byte boundary before `call`.                                | 16-byte boundary.                                               |
| **Shadow Space**             | No. Has a 128-byte "red zone" below `RSP`.                      | Yes, caller allocates 32 bytes on stack for the callee.        | No.                                                             |

### Deep Dive: System V AMD64 Aggregate Classification

*File: `abi_sysv_x64.c`*

The System V ABI has the most complex rules for passing aggregates (structs/unions). The logic is implemented in `classify_aggregate_sysv` and `classify_recursive`.

*   **Eightbytes**: An aggregate up to 16 bytes is conceptually split into one or two 8-byte chunks called "eightbytes".
*   **Classification**: Each field of the struct is examined recursively. Its type determines the class of the eightbyte(s) it falls into.
    *   `INTEGER`: The eightbyte contains integer types, pointers, or a mix of integer and float. It will be passed in a GPR.
    *   `SSE`: The eightbyte contains only `float` or `double` types. It will be passed in an XMM register.
    *   `MEMORY`: The aggregate is too large (> 16 bytes), contains unaligned fields, or contains special types like `long double`. It must be passed on the stack.
*   **Result**: This classification can result in a single struct being passed across two different register types (e.g., one GPR and one XMM), which is handled by the `ARG_LOCATION_GPR_SSE_PAIR` logic.

### Deep Dive: Windows x64 By-Reference Rule

*File: `abi_win_x64.c`*

The Windows x64 ABI uses a much simpler rule for aggregates, implemented in the `is_passed_by_reference` helper.

*   **Power-of-Two Rule**: An aggregate (or even a primitive like `long double`) is passed **by reference** (a pointer is passed in a GPR) if its size in bytes is **not** 1, 2, 4, or 8.
*   **Shared Slots**: The first four argument "slots" are used for both GPRs and XMMs. For a function `void(int, double, int, double)`, the arguments are passed in `RCX`, `XMM1`, `R8`, and `XMM3`. `RDX` (the second GPR slot) and `XMM0` (the first XMM slot) are skipped because the slots were consumed by arguments of a different type.

### Deep Dive: AArch64 Homogeneous Floating-point Aggregates (HFA)

*File: `abi_arm64.c`*

The ARM64 ABI has a special rule for compact structs containing only floating-point types, implemented in the `is_hfa` function.

*   **Definition**: An HFA is a struct or array containing 1 to 4 elements of the *exact same* floating-point type (`float` or `double`), even if nested. For example, `struct Point { double x, y; }; struct Line { Point p1; Point p2; }` is an HFA of four `double`s.
*   **Passing**: If a type is identified as an HFA, it is passed directly in up to four consecutive Vector/FP Registers (`V0`-`V7`), instead of by reference. This is a significant performance optimization.
*   **Apple ABI Divergence**: A critical platform-specific rule is handled for macOS on AArch64: all variadic arguments are passed on the stack. The standard AAPCS64 passes them in registers if available. This is handled by a preprocessor check in `prepare_forward_call_frame_arm64`.

---

## The Debugging Guide

This guide is for library maintainers and advanced contributors who need to debug the low-level machine code generated by `infix`.

### Introduction

Debugging Just-In-Time compiled code can feel like black magic. The code you're stepping through doesn't exist in any source file; it's a raw sequence of bytes in an executable memory page. However, with the right tools and techniques, it's entirely manageable.

This guide covers the two primary methods for inspecting the machine code generated by infix: using the built-in `DumpHex` utility and stepping through the code live with a debugger like GDB or WinDbg.

### Method 1: Static Analysis with `DumpHex`

The simplest way to see what the JIT is producing is to print it. infix provides a `DumpHex` utility (in `utility.h`) that is enabled in debug builds.

After you generate a trampoline, you can access its internal `exec` handle and print the contents of its executable memory region.

```c
#include <infix.h>
#include <utility.h> // Required for DumpHex

// The handle is opaque in the public API, but for debugging, you can
// temporarily expose the ffi_trampoline_handle_t struct in infix.h
if (trampoline) {
    DumpHex(trampoline->exec.rx_ptr, trampoline->exec.size, "My Trampoline");
}
```
This will produce a detailed hexdump of the generated machine code, which you can then compare against an instruction set reference for your architecture (e.g., the Intel/AMD developer manuals or the ARM Architecture Reference Manual).

```
# My Forward Trampoline (size: 78 bytes)
#   0x0000: 55 48 89 e5 41 54 41 55  41 56 41 57 49 89 cc 49 | UH..ATAUAVAWI..I
#   0x0010: 89 d5 4d 89 c6 48 81 ec  20 00 00 00 4c 89 e9 4d | ..M..H.. ...L..M
#   ...
```

### Method 2: Live Debugging with GDB (Linux/macOS)

This is the most powerful method. It allows you to step through the JIT'd code one instruction at a time and inspect the state of the CPU registers.

Let's say you've found a failure that you think is a bug in infix itself. Let's imagine a trampoline that wraps `int(int, int)` is failing. The arguments seem to be corrupted. These are the steps I would take:

    1.  **Get the Address**: Print the address of the executable code right after it's generated.

        ```c
        ffi_cif_func cif_func = (ffi_cif_func)ffi_trampoline_get_code(trampoline);
        printf("DEBUG: Trampoline generated at address: %p\n", (void*)cif_func);
        fflush(stdout);
        ```

    2.  **Run Under GDB**: `gdb ./my_test_executable`

    3.  **Set Breakpoint**:  Use the address you printed in step 1 to set a breakpoint. The `*` is crucial—it tells GDB to set a breakpoint on the memory address itself, not on a symbol.

        ```gdb
        (gdb) run
        # Your program will run and print the address
        DEBUG: Trampoline generated at address: 0x7ffff7fde000

        # Now, set the breakpoint
        (gdb) b *0x7ffff7fde000
        Breakpoint 1 at 0x7ffff7fde000
        ```
    4.  **Trigger and Disassemble**: Run the program. When it breaks, use `disassemble` to view the JIT code.

        ```gdb
        # After the cif_func() is called in your C code...
        Breakpoint 1, 0x00007ffff7fde000 in ?? ()
        (gdb) disassemble
        Dump of assembler code for function 0x7ffff7fde000:
        => 0x00007ffff7fde000:  push   %rbp
           0x00007ffff7fde001:  mov    %rsp,%rbp
           0x00007ffff7fde004:  push   %r12
           ...
        End of assembler dump.
        ```

    5.  **Step and Verify**: Use `stepi` (step instruction) and `info registers` to walk through the code and check register values before the `call` instruction. At that point, all the argument registers (`rdi`, `rsi`, `xmm0`, etc.) should contain the correct values you passed in.

        ```gdb
        (gdb) # ... stepi until you are right before the call ...
        (gdb) info registers rdi rsi
        rdi            0x2a          42
        rsi            0x64          100
        # If the values here are correct, your trampoline code is likely correct.
        # If they are wrong, you can step backward to see where the wrong value was loaded.
        ```

### Method 3: Live Debugging with WinDbg (Windows)

The process on Windows is conceptually identical but uses different commands (`bp` to set breakpoint, `u` to unassemble, `r` to view registers, `t` to trace/step).

    1.  **Get the Address**: Same as with GDB, print the address of the trampoline.

    2.  **Run Under WinDbg**: `windbg.exe my_failing_test.exe`

    3.  **Set a Breakpoint**: Use the `bp` command.

        ```
        0:000> g ; Go until the address is printed
        DEBUG: Trampoline generated at address: 0x1ff0a70000
        0:000> bp 0x1ff0a70000
        ```

    4.  **Trigger the Trampoline**: Let the program continue with `g`. It will break at your JIT code's entry point.

    5.  **Unassemble and Inspect**: Use `u` (unassemble) to view the code and `r` (registers) to view the CPU state.

        ```
        0:000> u .
        my_failing_test!0x1ff0a70000:
        000001ff`0a700000 55              push    rbp
        000001ff`0a700001 4889e5          mov     rbp,rsp
        ...
        0:000> r
        rax=... rcx=... rdx=...
        ```

    6.  **Step**: Use `t` (trace) to step through one instruction at a time. Check the argument registers (`rcx`, `rdx`, `r8`, `r9`, `xmm0-3`) right before the final `call` instruction.

By using these techniques, you can demystify the JIT compilation process and effectively debug even the most complex ABI and code generation issues.
---

## External ABI Documentation

The current `infix` implementations are based on the official ABI documents for each platform.

*   **System V AMD64 ABI:**
    *   [Main Specification (PDF)](https://github.com/hjl-tools/x86-psABI/wiki/x86-64-psABI-1.0.pdf)
*   **Microsoft Windows x64 ABI:**
    *   [Official Microsoft Documentation](https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention)
*   **ARM 64-bit (AArch64) ABI (AAPCS64):**
    *   [Official ARM Developer Documentation](https://github.com/ARM-software/abi-aa/releases/download/2025Q1/aapcs32.pdf)
    *   [Writing ARM64 code for Apple platforms](https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms)

---

# License and Legal

Copyright (c) 2025 Sanko Robinson

This documentation is licensed under the Creative Commons Attribution 4.0 International License (CC BY 4.0). You are free to share and adapt this material for any purpose, provided you give appropriate credit.

For the full license text, see the [LICENSE-CC](LICENSE-CC) file or visit [https://creativecommons.org/licenses/by/4.0/](https://creativecommons.org/licenses/by/4.0/).
