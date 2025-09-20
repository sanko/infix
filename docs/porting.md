# Porting `infix` to a New Platform

This guide outlines the steps required to add support for a new CPU architecture or Application Binary Interface (ABI) to the infix FFI library. We will use **RISC-V 64-bit (RV64GC)** with the standard **LP64D ABI** as a practical example.

The library is designed to be highly portable, with a clean separation between platform-agnostic logic and ABI-specific implementations.

## Step 0: Research and Preparation

This is the most critical step. Before writing any code, you must understand the target ABI. For RISC-V, this means studying the official specification (e.g., https://riscv.org/wp-content/uploads/2024/12/riscv-calling.pdf).

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

If you can answer these questions, you're well on your way to implementing the new ABI.

## Step 1: Platform Detection (`infix.h`)

The first step is to teach the library how to recognize the new platform. Open `infix.h` and locate the "Host Platform and Architecture Detection" section.

1.  **Add Architecture Macro**: Add a new `#define FFI_ARCH_*` macro. The standard compiler macro for RISC-V is `__riscv`, and the bit width is checked with `__riscv_xlen`.

    ```c
    // In infix.h, after the x86-64 and AArch64 checks...
    #elif defined(__riscv) && __riscv_xlen == 64
    #define FFI_ARCH_RISCV64
    #else
    #error "Unsupported architecture."
    #endif
    ```

2.  **Add ABI Macro**: In the "Target ABI Logic Selection" section, define a new `FFI_ABI_*` macro based on the combination of OS and architecture. For RISC-V 64-bit, the standard ABI is LP64D.

    ```c
    // In infix.h, inside the #ifndef FFI_ABI_FORCED block...
    #if defined(FFI_ARCH_AARCH64)
      // ...
    #elif defined(FFI_ARCH_RISCV64)
      #define FFI_ABI_LP64D
    #elif defined(FFI_ARCH_X64)
      // ...
    #endif
    ```

## Step 2: Implement the ABI Specification

This is the core of the porting effort. You must provide a concrete implementation of the two ABI "specification" structs: `ffi_forward_abi_spec` and `ffi_reverse_abi_spec`.

1.  **Create New Files**: In the `abi/riscv/` directory, create the necessary files:
    *   `abi_riscv64.c`
    *   `abi_riscv64_common.h`
    *   `abi_riscv64_emitters.c`
    *   `abi_riscv64_emitters.h`

2.  **Define Register Enums (`abi_riscv64_common.h`)**: Create enums for the general-purpose registers (GPRs) and floating-point registers (FPRs). This makes the code readable and type-safe.

```c
// In abi_riscv64_common.h
#pragma once
#include <stdint.h>

// General-Purpose Registers (GPRs)
typedef enum {
    ZERO_REG = 0, RA_REG = 1, SP_REG = 2, GP_REG = 3, TP_REG = 4,
    T0_REG = 5, T1_REG = 6, T2_REG = 7,
    S0_FP_REG = 8, S1_REG = 9,
    A0_REG = 10, A1_REG = 11, A2_REG = 12, A3_REG = 13,
    A4_REG = 14, A5_REG = 15, A6_REG = 16, A7_REG = 17,
    S2_REG = 18, S3_REG = 19, /* ... s4-s11 ... */
    T3_REG = 28, T4_REG = 29, T5_REG = 30, T6_REG = 31
} riscv_gpr;

// Floating-Point Registers (FPRs)
typedef enum {
    FT0_REG = 0, /* ... ft0-ft7 ... */
    FS0_REG = 8, FS1_REG = 9,
    FA0_REG = 10, FA1_REG = 11, FA2_REG = 12, FA3_REG = 13,
    FA4_REG = 14, FA5_REG = 15, FA6_REG = 16, FA7_REG = 17,
    FS2_REG = 18, /* ... fs2-fs11 ... */
    FT8_REG = 28, /* ... ft8-ft11 ... */
} riscv_fpr;
```

3.  **Implement ABI Logic (`abi_riscv64.c`)**: Define your spec v-tables and implement the ten required functions. The most critical function is `prepare_forward_call_frame_riscv64`. Your implementation must correctly apply the LP64D ABI rules:
    *   The first 8 integer/pointer arguments are passed in GPRs `a0`-`a7` (`x10`-`x17`).
    *   The first 8 floating-point arguments are passed in FPRs `fa0`-`fa7` (`f10`-`f17`).
    *   Small aggregates (<= 16 bytes) are passed by value, potentially in two GPRs (`a0`, `a1`).
    *   Larger aggregates are passed by reference.
    *   Return values are passed in `a0`/`a1` for integers/structs and `fa0`/`fa1` for floats. Larger structs are returned via a hidden pointer passed by the caller in `a0`.

```c
#include <infix.h>
#include "abi_riscv_common.h"
#include "abi_riscv_emitters.h" // We will create this next

// Forward Declarations for all required functions

// Forward Spec
static ffi_status prepare_forward_call_frame_riscv(/*...*/>);
static ffi_status generate_forward_prologue_riscv(/*...*/>);
static ffi_status generate_forward_argument_moves_riscv(/*...*/>);
static ffi_status generate_forward_epilogue_riscv(/*...*/>);

// Reverse Spec
static ffi_status prepare_reverse_call_frame_riscv(/*...*/>);
static ffi_status generate_reverse_prologue_riscv(/*...*/>);
static ffi_status generate_reverse_argument_marshalling_riscv(/*...*/>);
static ffi_status generate_reverse_dispatcher_call_riscv(/*...*/>);
static ffi_status generate_reverse_epilogue_riscv(/*...*/>);

// ABI Specification Instances

const ffi_forward_abi_spec g_riscv_forward_spec = {
    .prepare_forward_call_frame      = prepare_forward_call_frame_riscv,
    .generate_forward_prologue       = generate_forward_prologue_riscv,
    .generate_forward_argument_moves = generate_forward_argument_moves_riscv,
    .generate_forward_epilogue       = generate_forward_epilogue_riscv
};

const ffi_reverse_abi_spec g_riscv_reverse_spec = {
    .prepare_reverse_call_frame            = prepare_reverse_call_frame_riscv,
    .generate_reverse_prologue             = generate_reverse_prologue_riscv,
    .generate_reverse_argument_marshalling = generate_reverse_argument_marshalling_riscv,
    .generate_reverse_dispatcher_call      = generate_reverse_dispatcher_call_riscv,
    .generate_reverse_epilogue             = generate_reverse_epilogue_riscv
};

// Implementation Skeletons

static ffi_status prepare_forward_call_frame_riscv(/*...*/) {
    // This is the core classification logic.
    // 1. Allocate the ffi_call_frame_layout struct.
    // 2. Check if the return type is a large aggregate passed by reference. If so,
    //    the first argument register (a0) is now consumed by a hidden pointer.
    // 3. Iterate through each argument ffi_type:
    //    - Classify it as integer, float, or aggregate.
    //    - If there are available registers (a0-a7, fa0-fa7), assign the argument
    //      to one and increment the corresponding register counter.
    //    - If no registers are left, assign it to a stack offset.
    // 4. Calculate the total stack space needed, ensuring 16-byte alignment.
    // 5. Populate and return the completed layout struct.
}

static ffi_status generate_forward_prologue_riscv(code_buffer* buf, /*...*/) {
    // Emit RISC-V assembly for:
    // 1. `addi sp, sp, -stack_size` (allocate stack frame)
    // 2. `sd ra, offset(sp)` (save return address)
    // 3. `sd s0, offset(sp)` (save frame pointer)
    // 4. `mv s0, sp` (establish new frame pointer)
    // 5. Save any other callee-saved registers that will be used by the trampoline.
}

// ... implement all other required functions ...
```

## Step 3: Implement the Instruction Emitters

In `abi_riscv64_emitters.c`, you will write functions to generate the 32-bit RISC-V machine code instructions.

For example, to emit `ld rd, offset(rs1)` (load 64-bit value), which uses the I-Type instruction format:

```c
// In abi_riscv64_emitters.h
#pragma once
#include <infix.h>
#include "abi_riscv64_common.h"

void emit_riscv64_addi(code_buffer* buf, riscv_gpr rd, riscv_gpr rs1, int16_t imm);
void emit_riscv64_ld(code_buffer* buf, riscv_gpr rd, riscv_gpr base, int16_t offset);
void emit_riscv64_sd(code_buffer* buf, riscv_gpr src, riscv_gpr base, int16_t offset);
void emit_riscv64_jalr(code_buffer* buf, riscv_gpr rd, riscv_gpr rs1, int16_t imm);
// ... and so on for fld, fsd, mv, etc.
```

```c
// In abi_riscv64_emitters.c
// Example implementation for an I-type instructions
void emit_riscv_addi(code_buffer* buf, riscv_gpr rd, riscv_gpr rs1, int16_t imm) {
    // The RISC-V ISA specifies the bit fields for each instruction type.
    // This function combines the parts into a single 32-bit word.
    // I-type: [imm(11:0)] [rs1] [funct3] [rd] [opcode]
    uint32_t instruction = 0;
    instruction |= ((uint32_t)imm & 0xFFF) << 20; // imm[11:0]
    instruction |= ((uint32_t)rs1 & 0x1F) << 15;  // rs1
    instruction |= (0b000) << 12;                 // funct3 for ADDI
    instruction |= ((uint32_t)rd & 0x1F) << 7;    // rd
    instruction |= 0b0010011;                     // Opcode for addi (add immediate0 arithmetic
    emit_int32(buf, instruction);
}

void emit_riscv64_ld(code_buffer* buf, riscv64_gpr rd, riscv64_gpr rs1, int16_t offset) {
    // I-Type format: | imm[11:0] | rs1 | funct3 | rd | opcode |
    uint32_t instruction = 0;
    instruction |= ((uint32_t)offset & 0xFFF) << 20; // imm[11:0]
    instruction |= ((uint32_t)rs1 & 0x1F) << 15;     // rs1
    instruction |= (0b011) << 12;                    // funct3 for ld
    instruction |= ((uint32_t)rd & 0x1F) << 7;       // rd
    instruction |= 0b0000011;                        // opcode for LOAD
    emit_int32(buf, instruction);
}
```
You will need to create similar emitters for `sd` (store), `jalr` (jump and link register for calls), and other necessary instructions.

## Step 4: Integrate the New ABI

1.  **Declare Extern Specs**: In `trampoline.c`, add an `extern` declaration for your new spec structs inside a new `#if defined(FFI_ABI_LP64D)` block.
2.  **Update `get_current_*_abi_spec()`**: In `trampoline.c`, add your new ABI to the `get_current_forward_abi_spec()` and `get_current_reverse_abi_spec()` functions.

    ```c
    // In trampoline.c
    // Add extern declarations at the top of the file
    #if defined(FFI_ABI_RISCV64)
    extern const ffi_forward_abi_spec g_riscv_forward_spec;
    extern const ffi_reverse_abi_spec g_riscv_reverse_spec;
    #endif

    // Update the get_current_forward_abi_spec function
    static const ffi_forward_abi_spec * get_current_forward_abi_spec() {
        // ...
    #elif defined(FFI_ABI_AAPCS64)
        return &g_arm64_forward_spec;
    #elif defined(FFI_ABI_RISCV64)
        return &g_riscv_forward_spec;
    #else
        return NULL;
    #endif
    }

    // Do the same for get_current_reverse_abi_spec
    ```
3.  **Unity Build**: At the bottom of `trampoline.c`, add an `#include` for your new `.c` files.

    ```c
    #elif defined(FFI_ABI_LP64D)
    #include "abi_riscv64.c"
    #include "abi_riscv64_emitters.c"
    #endif
    ```

## Step 5: Testing

This is the most important step. You must compile and run the entire test suite on your new target platform, either on real hardware or an emulator like QEMU.

```bash
# From the build directory on your RISC-V system
make test
```

All tests should pass. Pay special attention to tests for aggregate passing (`101_by_value.c`, `102_by_reference.c`). You should add a new subtest to `101_by_value.c` that specifically verifies the passing of a 16-byte struct in the `a0` and `a1` registers, as this is a key feature of the RISC-V ABI.

---

# License and Legal

Copyright (c) 2025 Sanko Robinson

This documentation is licensed under the Creative Commons Attribution 4.0 International License (CC BY 4.0). You are free to share and adapt this material for any purpose, provided you give appropriate credit.

For the full license text, see the [LICENSE-CC](LICENSE-CC) file or visit [https://creativecommons.org/licenses/by/4.0/](https://creativecommons.org/licenses/by/4.0/).
