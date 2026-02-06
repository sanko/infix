# Porting infix to a New ABI

This guide outlines the steps required to add support for a new CPU architecture or Application Binary Interface (ABI) to the `infix` FFI library. The library is designed to be highly portable, with a clean separation between platform-agnostic logic and ABI-specific implementations.

We will use **RISC-V 64-bit (RV64GC)** with the standard **LP64D ABI** as a practical example throughout this guide.

## Step 0: Research and Preparation

This is the most critical step. Before writing any code, you must have a solid understanding of the target ABI specification. For RISC-V, this means studying the official calling convention document.

You need to answer these key questions:

*   **Integer/Pointer Argument Registers:** Which registers are used and in what order?
    *   *RISC-V Answer:* `a0` through `a7` (also known as `x10` through `x17`).
*   **Floating-Point Argument Registers:** Which registers are used for `float` and `double`?
    *   *RISC-V Answer:* `fa0` through `fa7` (also known as `f10` through `f17`).
*   **Return Value Registers:** Where are integer, pointer, and floating-point values returned?
    *   *RISC-V Answer:* `a0` and `a1` for integers/pointers up to 128 bits. `fa0` and `fa1` for floats/doubles.
*   **Aggregate Passing Rules (Structs/Unions):**
    *   How are small structs passed? Can they be split across multiple registers (GPRs and/or FPRs)?
    *   *RISC-V Answer:* Small aggregates that fit into two registers are passed by value. The content of the struct determines if they go in GPRs (`a...`) or FPRs (`fa...`).
    *   When are they passed by reference (a pointer is passed instead)?
    *   *RISC-V Answer:* Aggregates that are too large or have a non-trivial layout are passed by reference.
*   **Return by Hidden Pointer:** When is a struct returned via a hidden pointer passed by the caller? Which register is used for this pointer?
    *   *RISC-V Answer:* Large aggregates are returned via a hidden pointer passed in `a0`.
*   **Callee-Saved Registers:** Which registers must be preserved by a called function?
    *   *RISC-V Answer:* The frame pointer (`s0`/`fp`), the return address (`ra`), and the saved registers `s1` through `s11`.
*   **Stack Layout:** What is the required stack alignment? Is there a "red zone" or "shadow space"?
    *   *RISC-V Answer:* The stack must be 16-byte aligned. There is no red zone.

## Step 1: Platform Detection (`src/common/infix_config.h`)

The first code change is to teach the library how to recognize the new platform at compile time. Open `src/common/infix_config.h`.

1.  **Add Architecture Macro**: Locate the processor architecture detection block and add a new `#define INFIX_ARCH_*` macro. The standard compiler macro for RISC-V is `__riscv`, and the bit width is checked with `__riscv_xlen`.

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
      #define INFIX_ABI_LP64D // LP64D is the standard RISC-V ABI
    #elif defined(INFIX_ARCH_X64)
      // ...
    #endif
    ```

## Step 2: Implement the ABI Specification

This is the core of the porting effort. You must provide a concrete implementation of the two ABI "specification" v-tables: `infix_forward_abi_spec` and `infix_reverse_abi_spec`.

1.  **Create New Files**: Create a new directory for your architecture, `src/arch/riscv64/`, and add the necessary files. It's best to copy and adapt from an existing architecture like `aarch64`.
    *   `abi_riscv64.c`
    *   `abi_riscv64_common.h`
    *   `abi_riscv64_emitters.c`
    *   `abi_riscv64_emitters.h`

2.  **Define Register Enums (`abi_riscv64_common.h`)**: Create enums for the general-purpose registers (GPRs) and floating-point registers (FPRs). The enum values should correspond to their 5-bit encoding in machine code.

    ```c
    // In src/arch/riscv64/abi_riscv64_common.h
    typedef enum {
        ZERO_REG = 0, RA_REG = 1, SP_REG = 2, /* ... */ A0_REG = 10, A1_REG = 11, /* ... */
    } riscv_gpr;

    typedef enum {
        FT0_REG = 0, /* ... */ FA0_REG = 10, FA1_REG = 11, /* ... */
    } riscv_fpr;
    ```

3.  **Implement ABI Logic (`abi_riscv64.c`)**: This file will contain the implementations for the ten functions required by the ABI specs. The `prepare_forward_call_frame` function is the most complex, as it must correctly apply all the ABI rules you researched in Step 0.

    ```c
    // In src/arch/riscv64/abi_riscv64.c
    #include "common/infix_internals.h"
    #include "abi_riscv64_common.h"
    #include "abi_riscv64_emitters.h"

    // Forward Declarations for all 10 required static functions...
    static infix_status prepare_forward_call_frame_riscv64(...);
    static infix_status generate_forward_prologue_riscv64(...);
    // ... etc. for all 10 functions.

    // Define the ABI Specification V-Table Instances
    const infix_forward_abi_spec g_riscv_forward_spec = {
        .prepare_forward_call_frame = prepare_forward_call_frame_riscv64,
        .generate_forward_prologue = generate_forward_prologue_riscv64,
        // ... fill in all 5 function pointers
    };
    const infix_reverse_abi_spec g_riscv_reverse_spec = {
        .prepare_reverse_call_frame = prepare_reverse_call_frame_riscv64,
        // ... fill in all 5 function pointers
    };

    // Implementation of all 10 functions...
    static infix_status prepare_forward_call_frame_riscv64(/*...*/) {
        // Core classification logic:
        // 1. Allocate the layout struct from the provided arena.
        // 2. Check for return-by-reference (consumes a0).
        // 3. Loop through arguments, classifying each one.
        // 4. Assign arguments to a0-a7, fa0-fa7, or the stack based on classification.
        // 5. Calculate total stack space needed and return the completed layout.
    }
    // ... implement the other 9 functions ...
    ```

## Step 3: Implement the Instruction Emitters

In `src/arch/riscv64/abi_riscv64_emitters.c` and its header, you will write small, focused functions to generate the 32-bit RISC-V machine code instructions. Each function will assemble the bitfields specified in the ISA manual.

**Example Emitter for `LD` (Load Doubleword):**
```c
// In src/arch/riscv64/abi_riscv64_emitters.h
void emit_riscv64_ld(code_buffer* buf, riscv_gpr rd, riscv_gpr base, int16_t offset);

// In src/arch/riscv64/abi_riscv64_emitters.c
void emit_riscv64_ld(code_buffer* buf, riscv_gpr rd, riscv_gpr base, int16_t offset) {
    // I-Type instruction format: | imm[11:0] | rs1 | funct3 | rd | opcode |
    uint32_t instruction = 0;
    instruction |= ((uint32_t)offset & 0xFFF) << 20;  // 12-bit immediate
    instruction |= ((uint32_t)base & 0x1F) << 15;     // 5-bit rs1 (base register)
    instruction |= (0b011) << 12;                     // funct3 for ld
    instruction |= ((uint32_t)rd & 0x1F) << 7;        // 5-bit rd (destination register)
    instruction |= 0b0000011;                         // opcode for LOAD

    // The emit_int32 helper function appends the final instruction to the code buffer.
    emit_int32(buf, instruction);
}
```

## Step 4: Integrate the New ABI

The final step is to hook your new implementation into the main trampoline engine.

1.  **Update `infix_internals.h`**: Add an include for your new emitters header inside the architecture-specific block at the bottom of the file.
    ```c
    // In src/common/infix_internals.h
    #if defined(INFIX_ABI_SYSV_X64) || defined(INFIX_ABI_WINDOWS_X64)
    #include "arch/x64/abi_x64_emitters.h"
    #elif defined(INFIX_ABI_AAPCS64)
    #include "arch/aarch64/abi_arm64_emitters.h"
    #elif defined(INFIX_ABI_LP64D)
    #include "arch/riscv64/abi_riscv64_emitters.h" // Add this line
    #endif
    ```
2.  **Update `trampoline.c`**:
    *   Add an `extern` declaration for your new spec v-tables inside a new `#if defined(INFIX_ABI_LP64D)` block.
    *   Add your new ABI to the `get_current_forward_abi_spec()` and `get_current_reverse_abi_spec()` functions.
    *   Add your new `.c` files to the unity build section at the very end of the file.

    ```c
    // In src/core/trampoline.c

    // ... near the top ...
    #elif defined(INFIX_ABI_AAPCS64)
    extern const infix_forward_abi_spec g_arm64_forward_spec;
    extern const infix_reverse_abi_spec g_arm64_reverse_spec;
    #elif defined(INFIX_ABI_LP64D)
    extern const infix_forward_abi_spec g_riscv_forward_spec;
    extern const infix_reverse_abi_spec g_riscv_reverse_spec;
    #endif

    // ... in get_current_forward_abi_spec() ...
    #elif defined(INFIX_ABI_AAPCS64)
        return &g_arm64_forward_spec;
    #elif defined(INFIX_ABI_LP64D)
        return &g_riscv_forward_spec;
    #else

    // ... (repeat for get_current_reverse_abi_spec) ...

    // ... at the very bottom (unity build section) ...
    #elif defined(INFIX_ABI_AAPCS64)
    #include "../arch/aarch64/abi_arm64.c"
    #include "../arch/aarch64/abi_arm64_emitters.c"
    #elif defined(INFIX_ABI_LP64D)
    #include "../arch/riscv64/abi_riscv64.c"
    #include "../arch/riscv64/abi_riscv64_emitters.c"
    #else
    #error "No supported ABI was selected for the unity build in trampoline.c."
    #endif
    ```

## Step 5: Testing

Once the library compiles for your new target, the final and most important step is to run the entire test suite. This is best done on real hardware, but a high-fidelity emulator like QEMU can also be used.

-   Pay special attention to the results of tests `101_by_value.c`, `102_by_reference.c`, and `402_variadic_functions.c`, as these are the most likely to reveal subtle ABI implementation errors.
-   Run the memory stress tests under Valgrind (if available on the target) to check for leaks.
-   If possible, run the fuzzing harnesses on the new target to shake out edge cases.

## Step 6: Exception Handling Support (Optional but Recommended)

To support transparent exception propagation and Safe Boundaries, you must provide the platform's unwinding metadata.

*   **For Windows x64:** Ensure your prologue is standard (`push rbp; mov rbp, rsp`) and populate the `RUNTIME_FUNCTION` and `UNWIND_INFO` structures in `executor.c`.
*   **For ELF/DWARF (Linux/macOS):** You must generate `.eh_frame` records (CIE and FDE) that describe your trampoline's stack frame. See the existing implementations in `executor.c` for examples.
*   **Safe Boundaries:** Implementing `infix_forward_create_safe` requires a platform-specific personality routine that can intercept exceptions and redirect execution to the trampoline's epilogue.
