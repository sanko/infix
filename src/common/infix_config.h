#pragma once
/**
 * Copyright (c) 2025 Sanko Robinson
 *
 * This source code is dual-licensed under the Artistic License 2.0 or the MIT License.
 * You may choose to use this code under the terms of either license.
 *
 * SPDX-License-Identifier: (Artistic-2.0 OR MIT)
 *
 * The documentation blocks within this file are licensed under the
 * Creative Commons Attribution 4.0 International License (CC BY 4.0).
 *
 * SPDX-License-Identifier: CC-BY-4.0
 */
/**
 * @file infix_config.h
 * @brief Internal-only header for platform, architecture, and ABI detection.
 * @copyright Copyright (c) 2025 Sanko Robinson
 *
 * @details
 * This header contains the complete logic for detecting the build environment.
 * It is included by `infix_internals.h` and is NOT part of the public API.
 * Exposing these macros in the public API would make them part of the library's
 * contract, preventing them from being changed or improved without breaking
 * user code that might depend on them. Keeping them internal ensures a stable
 * public API and a decoupled ecosystem.
 *
 * The following preprocessor macros will be defined based on the build environment:
 *
 * Operating System:
 * - INFIX_OS_WINDOWS:       Microsoft Windows
 * - INFIX_OS_MACOS:         Apple macOS
 * - INFIX_OS_IOS:           Apple iOS
 * - INFIX_OS_LINUX:         Linux (excluding Android)
 * - INFIX_OS_ANDROID:       Android
 * - INFIX_OS_TERMUX:        Termux on Android
 * - INFIX_OS_FREEBSD:       FreeBSD
 * - INFIX_OS_OPENBSD:       OpenBSD
 * - INFIX_OS_NETBSD:        NetBSD
 * - INFIX_OS_DRAGONFLY:     DragonFly BSD
 * - INFIX_OS_SOLARIS:       Oracle Solaris
 * - INFIX_OS_HAIKU:         Haiku OS
 *
 * Processor Architecture:
 * - INFIX_ARCH_X64:         x86-64 / AMD64
 * - INFIX_ARCH_AARCH64:     ARM64
 * - INFIX_ARCH_X86:         x86 (32-bit)
 * - INFIX_ARCH_ARM:         ARM (32-bit)
 *
 * Application Binary Interface (ABI):
 * - INFIX_ABI_WINDOWS_X64:  Microsoft x64 Calling Convention
 * - INFIX_ABI_SYSV_X64:     System V AMD64 ABI
 * - INFIX_ABI_AAPCS64:      ARM 64-bit Procedure Call Standard
 *
 * Compiler:
 * - INFIX_COMPILER_MSVC:    Microsoft Visual C++
 * - INFIX_COMPILER_CLANG:   Clang
 * - INFIX_COMPILER_GCC:     GNU Compiler Collection
 * - INFIX_COMPILER_INTEL:   Intel C/C++ Compiler
 * - INFIX_COMPILER_IBM:     IBM XL C/C++
 * - INFIX_COMPILER_NFI:     Unknown compiler
 *
 * Environment:
 * - INFIX_ENV_POSIX:         Defined for POSIX-compliant systems (macOS, Linux, BSDs, etc.)
 * - INFIX_ENV_MSYS:         MSYS/MSYS2 build environment
 * - INFIX_ENV_CYGWIN:       Cygwin environment
 * - INFIX_ENV_MINGW:        MinGW/MinGW-w64 compilers
 * - INFIX_ENV_TERMUX:       Termux running on Android or Chrome OS
 *
 */

// Define the POSIX source macro to ensure function declarations for shm_open,
// ftruncate, etc., are visible on all POSIX-compliant systems.
#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#if (defined(__linux__) || defined(__gnu_linux__)) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

// Host Platform and Architecture Detection
// This block ALWAYS detects the native host. It is NOT overridden by the ABI flag.
#if defined(_WIN32)
#define INFIX_OS_WINDOWS
#include <windows.h>
#if defined(__MSYS__)
#define INFIX_ENV_MSYS 1
#elif defined(__CYGWIN__)
#define INFIX_ENV_CYGWIN 1
#define INFIX_ENV_POSIX 1
#elif defined(__MINGW32__) || defined(__MINGW64__)
#define INFIX_ENV_MINGW 1
#endif
#elif defined(__TERMUX__)
#define INFIX_OS_TERMUX
#define INFIX_OS_ANDROID  // Container
#define INFIX_OS_LINUX
#define INFIX_ENV_POSIX
#define INFIX_ENV_TERMUX 1
#elif defined(__ANDROID__)
#define INFIX_OS_ANDROID
#define INFIX_OS_LINUX  // Android is close enough...
#define INFIX_ENV_POSIX
#elif defined(__APPLE__)
#define INFIX_ENV_POSIX
#define _DARWIN_C_SOURCE
#include <TargetConditionals.h>
#include <libkern/OSCacheControl.h>
#include <pthread.h>
#if TARGET_IPHONE_SIMULATOR || TARGET_OS_IPHONE
#define INFIX_OS_IOS
#elif TARGET_OS_MAC
#define INFIX_OS_MACOS
#else
#error "Unsupported/unknown Apple platform"
#endif
#elif defined(__linux__)
#define INFIX_OS_LINUX
#define INFIX_ENV_POSIX
#elif defined(__FreeBSD__)
#define INFIX_OS_FREEBSD
#define INFIX_ENV_POSIX
#elif defined(__OpenBSD__)
#define INFIX_OS_OPENBSD
#define INFIX_ENV_POSIX
#elif defined(__NetBSD__)
#define INFIX_OS_NETBSD
#define INFIX_ENV_POSIX
#elif defined(__DragonFly__)
#define INFIX_OS_DRAGONFLY
#define INFIX_ENV_POSIX
#elif defined(__sun) && defined(__SVR4)
#define INFIX_OS_SOLARIS
#define INFIX_ENV_POSIX
#elif defined(__HAIKU__)
#define INFIX_OS_HAIKU
#define INFIX_ENV_POSIX
#else
#warning "Unsupported/unknown operating system"
#endif

#if defined(__clang__)
#define INFIX_COMPILER_CLANG
#elif defined(_MSC_VER)
#define INFIX_COMPILER_MSVC
#elif defined(__GNUC__)
#define INFIX_COMPILER_GCC
#else
#warning "Compiler: Unknown compiler detected."
#define INFIX_COMPILER_NFI
#endif

#if defined(__aarch64__) || defined(_M_ARM64)
#define INFIX_ARCH_AARCH64
#elif defined(__x86_64__) || defined(_M_X64)
#define INFIX_ARCH_X64
#else
#error "Unsupported architecture. Only x86-64 and AArch64 are currently supported."
#endif

// Target ABI Logic Selection
// This block determines which ABI implementation to use. It can be overridden
// by a compiler flag, which is useful for cross-ABI testing and fuzzing.

#if defined(INFIX_FORCE_ABI_WINDOWS_X64)
#define INFIX_ABI_WINDOWS_X64 1
#define INFIX_ABI_FORCED 1
#elif defined(INFIX_FORCE_ABI_SYSV_X64)
#define INFIX_ABI_SYSV_X64 1
#define INFIX_ABI_FORCED 1
#elif defined(INFIX_FORCE_ABI_AAPCS64)
#define INFIX_ABI_AAPCS64 1
#define INFIX_ABI_FORCED 1
#endif

// If no ABI was forced, detect it based on the host architecture.
#ifndef INFIX_ABI_FORCED
#if defined(INFIX_ARCH_AARCH64)
#define INFIX_ABI_AAPCS64
#elif defined(INFIX_ARCH_X64)
#if defined(INFIX_OS_WINDOWS)
#define INFIX_ABI_WINDOWS_X64
#else
#define INFIX_ABI_SYSV_X64
#endif
#endif
#endif
