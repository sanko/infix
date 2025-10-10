/**
 * @file infix.c
 * @brief The unity build source file for the infix library.
 * @ingroup internal_core
 *
 * @internal
 * This file acts as the single translation unit for the entire infix library. It
 * includes all other necessary C source files in a specific order to resolve
 * dependencies and create the final library object.
 *
 * Using a unity build simplifies the project's build process and can enable more
 * aggressive cross-file optimizations by the compiler.
 *
 * To maintain proper encapsulation, all functions within the included source files
 * (except for the public API declared in infix.h) should be declared as `static`.
 *
 * @note This file is not intended to be compiled on its own without the
 * rest of the source tree. It is the entry point for the build system.
 * @endinternal
 */

/*
 * The order of inclusion is important to respect dependencies. The files are ordered
 * from the most foundational components to the highest-level ones.
 */
// 1. Error Messages: Provides information about internal errors.
#include "core/error.c"
// 2. Arena Allocator: The fundamental memory management component.
#include "core/arena.c"
// 3. OS Executor: Handles OS-level memory management for executable code.
#include "core/executor.c"
// 4. Type Registry: The new module for managing named types. Depends on arena.
#include "core/type_registry.c"
// 5. Signature Parser: Implements the high-level string-based API; depends on types, arena, and registry.
#include "core/signature.c"
// 6. Loader: Implements the low-level file loading and parsing logic; depends on types and arena. Platform independent.
#include "core/loader.c"
// 7. Type System: Defines and manages `infix_type` objects; depends on the arena.
#include "core/types.c"
// 8. Debugging Utilities: Low-level helpers for logging and inspection.
#include "core/utility.c"
// 9. Trampoline Engine: The central JIT compiler. This must be last, as it depends on all
//    other components and includes the final ABI- and architecture-specific C files itself.
#include "core/trampoline.c"
