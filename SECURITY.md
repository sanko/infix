# Security Policy

This document outlines the security policy for `infix`.

The `infix` FFI library was designed with a security-first philosophy. Interfacing with C and generating executable code at runtime are inherently sensitive operations. This document outlines our threat model and the specific mitigations implemented to ensure the library is as safe and robust as possible.

## Supported Versions

Security updates are provided for the latest public release. As this is a pre-1.0 project, users are encouraged to stay on the most recent commit from the main development branch.

| Version       | Supported          |
| ------------- | ------------------ |
| >= 0.1.0      | :white_check_mark: |
| < 0.1.0       | :x:                |
| [unversioned] | :white_check_mark: |

## Reporting a Vulnerability

I take all security vulnerabilities seriously. To protect the project's users, I request that you report all suspected vulnerabilities to me privately.

**Please do not report security vulnerabilities through public GitHub issues.**

The preferred and most secure method for reporting is through **[GitHub's private vulnerability reporting feature](https://github.com/sanko/infix/security/advisories/new)**. This creates a private advisory and opens a direct, secure line of communication.

If you are unable to use GitHub's reporting feature, you may send an email to [sanko@cpan.org](mailto:sanko@cpan.org).

Please include the following information in your report:

*   A detailed description of the vulnerability and how to reproduce it.
*   The version(s) or commit hash of the library affected.
*   Any proof-of-concept code or steps that demonstrate the issue.
*   The potential impact of the vulnerability (e.g., code execution, information disclosure).

I will do my best to acknowledge your report within 48 hours and will work with you to understand and resolve the issue. I will publicly credit you for your discovery once the vulnerability has been patched, unless you prefer to remain anonymous.

# Security Model

We consider the following to be the primary security threats for an FFI library:

1.  **Code Injection / JIT-Spraying**: An attacker providing malicious data that is inadvertently written into an executable memory region and later executed.
2.  **API Abuse & Memory Corruption**: An attacker providing malformed type descriptions (e.g., with incorrect sizes or offsets) to the API, causing integer overflows that lead to buffer overflows or other memory corruption inside the library.
3.  **Use-After-Free Vulnerabilities**: An attacker causing the program to call a function pointer from a trampoline that has already been freed, potentially leading to arbitrary code execution.
4.  **Runtime State Corruption**: An attacker modifying the internal state of a callback (reverse trampoline) after its creation to hijack its behavior.

## Mitigations

`infix` employs several layers of defense to mitigate these threats.

### 1. W^X (Write XOR Execute) Memory Policy

**The most critical security feature of `infix` is its strict enforcement of a W^X memory policy.** Memory that is used for JIT-compiled trampolines is **never writable and executable at the same time**. This is a fundamental defense against code injection attacks.

This policy is implemented in `executor.c` using platform-specific, hardened techniques:

*   **On Hardened POSIX (Linux, FreeBSD)**: We use a **dual-mapping** technique. An anonymous shared memory object is created via `shm_open`. This object is then mapped into the process's virtual address space twice:
    *   One mapping is `PROT_READ | PROT_WRITE` (`rw_ptr`). Code is written here.
    *   A second, separate mapping is `PROT_READ | PROT_EXEC` (`rx_ptr`). Code is executed from here.
    Because the virtual addresses are different, it is impossible for an attacker to write to the executable mapping.

*   **On Windows**: We use the native `VirtualAlloc` and `VirtualProtect` APIs. Memory is allocated as `PAGE_READWRITE`. After the machine code has been written, its protection is changed to `PAGE_EXECUTE_READ`, revoking write permissions before the code is ever used.

*   **On macOS, OpenBSD, and others**: A reliable single-map `mmap` strategy is used. Memory is allocated as `PROT_READ | PROT_WRITE`. After code generation, `mprotect` is used to change the permissions to `PROT_READ | PROT_EXEC`.

### 2. Use-After-Free Prevention (Guard Pages)

When a trampoline is freed via `ffi_trampoline_free` or `ffi_reverse_trampoline_free`, the library does not simply release the memory.

First, the executable memory region's permissions are changed to be completely inaccessible (`PAGE_NOACCESS` on Windows, `PROT_NONE` on POSIX). This turns the region into a **guard page**. If any dangling function pointer attempts to call this freed code, the program will trigger an immediate and safe access violation (segmentation fault), rather than executing stale or unrelated data. This makes use-after-free bugs easy to detect and prevents them from being exploitable.

### 3. Read-Only Context Hardening

The `ffi_reverse_trampoline_t` context struct holds critical information about a callback, including the pointer to the user's handler function. To prevent an attacker from modifying this context at runtime, the entire structure is placed in a protected memory region.

After `generate_reverse_trampoline` successfully initializes the context, the memory page it resides on is made **read-only** using `VirtualProtect` or `mprotect`. Any subsequent attempt to write to this structure will result in a safe crash, preventing callback hijacking.

### 4. API Hardening Against Integer Overflows

The type creation API (`types.c`) is a potential attack surface. An attacker could provide malicious `size`, `offset`, or `num_elements` values to functions like `ffi_type_create_struct` and `ffi_type_create_array` in an attempt to trigger an integer overflow during layout calculations.

All such calculations in the `infix` library are hardened with checks against `SIZE_MAX` to prevent wrap-around. If a potential overflow is detected, the function will immediately fail with `FFI_ERROR_INVALID_ARGUMENT`, preventing the creation of a malformed `ffi_type` that could lead to memory corruption in later stages.

### 5. Continuous Security Validation (Fuzzing)

The library is continuously tested using modern fuzzing tools (libFuzzer and AFL++). The fuzzing harnesses in the `fuzz/` directory are designed to attack the most complex parts of the library:

*   **`fuzz_types`**: Attacks the type creation and destruction logic with deeply-nested, randomized, and invalid type definitions.
*   **`fuzz_trampoline`**: Attacks the ABI classification and code generation pipeline with randomized function signatures.

This ensures that our security mitigations are constantly validated against unexpected and malicious inputs.
