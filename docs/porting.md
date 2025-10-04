# Porting `infix` to a New Platform

This guide outlines the steps required to add support for a new CPU architecture or Application Binary Interface (ABI) to the infix FFI library. We will use **RISC-V 64-bit (RV64GC)** with the standard **LP64D ABI** as a practical example.

The library is designed to be highly portable, with a clean separation between platform-agnostic logic and ABI-specific implementations.

## Step 0: Research and Preparation

This is the most critical step. Before writing any code, you must have a solid understanding of the target ABI specification. For RISC-V, this means studying the official calling convention document.

You need to answer these key questions:

*   **Integer Argument Registers:** Which registers are used for integer and pointer arguments?
    *   *RISC-V Answer:* `a0` through `a7` (also known by their ABI names `x10` through `x17`).
*   **Floating-Point Argument Registers:** Which registers are used for `float` and `double` arguments?
    *   *RISC-V Answer:* `fa0` through `fa7` (also known as `f10` through `f17`).
*   **Return Value Registers:** Where are integer and floating-point values returned?
    *   *RISC-V Answer:* `a0` and `a1` for integers/pointers up to 128 bits. `fa0` and `fa1` for floats/doubles.
*   **Aggregate Passing Rules (Structs/Unions):**
    *   How are small structs passed? Can they be split across multiple registers?
    *   *RISC-V Answer:* Small aggregates that fit into two registers (GPRs or FPRs depending on content) are passed by value in registers.
    *   When are they passed by reference (a pointer is passed instead)?
    *   *RISC-V Answer:* Aggregates that are too large or have a non-trivial layout are passed by reference.
*   **Callee-Saved Registers:** Which registers must be preserved by a called function?
    *   *RISC-V Answer:* The frame pointer (`s0`/`fp`), the return address (`ra`), and the saved registers `s1` through `s11`.
*   **Stack Alignment:** What is the required stack alignment?
    *   *RISC-V Answer:* The stack must be 16-byte aligned.

## Step 1: Platform Detection (`src/common/infix_config.h`)

The first step is to teach the library how to recognize the new platform. Open `src/common/infix_config.h` and locate the architecture and ABI detection sections.

1.  **Add Architecture Macro**: Add a new `#define INFIX_ARCH_*` macro. The standard compiler macro for RISC-V is `__riscv`, and the bit width is checked with `__riscv_xlen`.

    ```c
    // In src/common/infix_config.h, after the other architecture checks...
    #elif defined(__riscv) && __riscv_xlen == 64
    #define INFIX_ARCH_RISCV64
    #else
    #error "Unsupported architecture."
    #endif
    ```

2.  **Add ABI Macro**: In the "Target ABI Logic Selection" section, define a new `INFIX_ABI_*` macro based on the combination of OS and architecture.

    ```c
    // In src/common/infix_config.h, inside the #ifndef INFIX_ABI_FORCED block...
    #if defined(INFIX_ARCH_AARCH64)
      // ...
    #elif defined(INFIX_ARCH_RISCV64)
      #define INFIX_ABI_LP64D
    #elif defined(INFIX_ARCH_X64)
      // ...
    #endif
    ```

## Step 2: Implement the ABI Specification

This is the core of the porting effort. You must provide a concrete implementation of the two ABI "specification" structs: `infix_forward_abi_spec` and `infix_reverse_abi_spec`.

1.  **Create New Files**: Create a new directory for your architecture, e.g., `src/arch/riscv64/`, and add the necessary files:
    *   `abi_riscv64.c`
    *   `abi_riscv64_common.h`
    *   `abi_riscv64_emitters.c`
    *   `abi_riscv64_emitters.h`

2.  **Define Register Enums (`abi_riscv64_common.h`)**: Create enums for the general-purpose registers (GPRs) and floating-point registers (FPRs).

    ```c
    // In src/arch/riscv64/abi_riscv64_common.h
    typedef enum {
        ZERO_REG = 0, RA_REG = 1, SP_REG = 2, /* ... */ A0_REG = 10, A1_REG = 11, /* ... */
    } riscv_gpr;

    typedef enum {
        FT0_REG = 0, /* ... */ FA0_REG = 10, FA1_REG = 11, /* ... */
    } riscv_fpr;
    ```

3.  **Implement ABI Logic (`abi_riscv64.c`)**: Define your spec v-tables and implement the ten required functions. `prepare_forward_call_frame_riscv64` is the most critical, as it must correctly apply all the ABI rules you researched in Step 0.

    ```c
    // In src/arch/riscv64/abi_riscv64.c
    #include "common/infix_internals.h"
    #include "abi_riscv64_common.h"
    #include "abi_riscv64_emitters.h"

    // Forward Declarations for all 10 required static functions...

    // ABI Specification V-Table Instances
    const infix_forward_abi_spec g_riscv_forward_spec = { /* .prepare = ..., etc. */ };
    const infix_reverse_abi_spec g_riscv_reverse_spec = { /* .prepare = ..., etc. */ };

    // Implementation of all 10 functions...
    static infix_status prepare_forward_call_frame_riscv64(/*...*/) {
        // Core classification logic:
        // 1. Allocate the layout struct.
        // 2. Check for return-by-reference (consumes a0).
        // 3. Loop through arguments, assigning them to a0-a7, fa0-fa7, or the stack.
        // 4. Calculate total stack space and return the layout.
    }
    // ...
    ```

## Step 3: Implement the Instruction Emitters

In `src/arch/riscv64/abi_riscv64_emitters.c`, you will write functions to generate the 32-bit RISC-V machine code instructions by assembling the bitfields specified in the ISA manual.

**Example Emitter for `LD` (Load Doubleword):**
```c
// In src/arch/riscv64/abi_riscv64_emitters.h
void emit_riscv64_ld(code_buffer* buf, riscv_gpr rd, riscv_gpr base, int16_t offset);

// In src/arch/riscv64/abi_riscv64_emitters.c
void emit_riscv64_ld(code_buffer* buf, riscv_gpr rd, riscv_gpr base, int16_t offset) {
    // I-Type format: | imm[11:0] | rs1 | funct3 | rd | opcode |
    uint32_t instruction = 0;
    instruction |= ((uint32_t)offset & 0xFFF) << 20;
    instruction |= ((uint32_t)base & 0x1F) << 15;
    instruction |= (0b011) << 12; // funct3 for ld
    instruction |= ((uint32_t)rd & 0x1F) << 7;
    instruction |= 0b0000011;     // opcode for LOAD
    emit_int32(buf, instruction);
}
```

## Step 4: Integrate the New ABI

1.  **Update `trampoline.c`**: This is the final step.
    *   Add an `extern` declaration for your new spec v-tables inside a new `#if defined(INFIX_ABI_LP64D)` block.
    *   Add your new ABI to the `get_current_forward_abi_spec()` and `get_current_reverse_abi_spec()` functions.
    *   Add your new `.c` files to the unity build section at the very end of the file.

    ```c
    // In src/core/trampoline.c

    // ... near the top ...
    #if defined(INFIX_ABI_LP64D)
    extern const infix_forward_abi_spec g_riscv_forward_spec;
    extern const infix_reverse_abi_spec g_riscv_reverse_spec;
    #endif

    // ... in get_current_forward_abi_spec() ...
    #elif defined(INFIX_ABI_LP64D)
        return &g_riscv_forward_spec;

    // ... at the very bottom (unity build section) ...
    #elif defined(INFIX_ABI_LP64D)
    #include "../arch/riscv64/abi_riscv64.c"
    #include "../arch/riscv64/abi_riscv64_emitters.c"
    #endif
    ```

## Step 5: Testing

Compile and run the entire test suite on your new target platform (either real hardware or an emulator like QEMU). Pay special attention to tests for aggregate passing (`struct`s and `union`s) and variadic functions.
