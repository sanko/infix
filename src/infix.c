/**
 * @file infix.c
 * @brief The unity build source file for the infix library.
 * @copyright Copyright (c) 2025 Sanko Robinson
 *
 * @details
 * This file is the single translation unit for the entire infix library. It
 * includes all other necessary C source files in the correct order to create
 * the final library object. This approach simplifies the build process and can
 * enable more aggressive compiler optimizations.
 *
 * All functions in the included files (except for the public API declared in
 * infix.h) should be declared as `static` to ensure they are properly
 * encapsulated within this translation unit.
 *
 * @note This file is not intended to be compiled on its own without the
 * rest of the source tree. It is the entry point for the build system.
 */

// Core component implementations.
// The order is important to respect dependencies.
#include "core/arena.c"
#include "core/executor.c"
#include "core/signature.c"
#include "core/types.c"
#include "core/utility.c"

// The trampoline generator is the central engine. It must be included last,
// as it, in turn, includes the ABI- and architecture-specific C files.
#include "core/trampoline.c"