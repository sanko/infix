/*
 @licstart  The following is the entire license notice for the JavaScript code in this file.

 The MIT License (MIT)

 Copyright (C) 1997-2020 by Dimitri van Heesch

 Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 and associated documentation files (the "Software"), to deal in the Software without restriction,
 including without limitation the rights to use, copy, modify, merge, publish, distribute,
 sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all copies or
 substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 @licend  The above is the entire license notice for the JavaScript code in this file
*/
var NAVTREE =
[
  [ "infix", "index.html", [
    [ "infix: A JIT-powered FFI library for C", "index.html", "index" ],
    [ "API Quick Reference", "md_docs_2API.html", [
      [ "Table of Contents", "md_docs_2API.html#autotoc_md13", null ],
      [ "1. High-Level Signature API", "md_docs_2API.html#autotoc_md15", [
        [ "Forward Trampolines (Calling C)", "md_docs_2API.html#autotoc_md16", [
          [ "<tt>infix_forward_create</tt>", "md_docs_2API.html#autotoc_md17", null ],
          [ "<tt>infix_forward_create_safe</tt>", "md_docs_2API.html#autotoc_md18", null ],
          [ "<tt>infix_forward_create_unbound</tt>", "md_docs_2API.html#autotoc_md19", null ],
          [ "<tt>infix_forward_create_in_arena</tt> (Advanced)", "md_docs_2API.html#autotoc_md20", null ]
        ] ],
        [ "Direct Marshalling (Advanced Language Bindings)", "md_docs_2API.html#autotoc_md21", [
          [ "<tt>infix_forward_create_direct</tt>", "md_docs_2API.html#autotoc_md22", null ],
          [ "<tt>infix_forward_get_direct_code</tt>", "md_docs_2API.html#autotoc_md23", null ]
        ] ],
        [ "Reverse Trampolines (Callbacks & Closures)", "md_docs_2API.html#autotoc_md24", [
          [ "<tt>infix_reverse_create_callback</tt>", "md_docs_2API.html#autotoc_md25", null ],
          [ "<tt>infix_reverse_create_closure</tt>", "md_docs_2API.html#autotoc_md26", null ]
        ] ],
        [ "Trampoline Destruction", "md_docs_2API.html#autotoc_md27", null ]
      ] ],
      [ "2. Error Handling API", "md_docs_2API.html#autotoc_md29", [
        [ "The Error Handling Pattern", "md_docs_2API.html#autotoc_md30", null ],
        [ "Common Error Categories", "md_docs_2API.html#autotoc_md31", [
          [ "Parser Errors (<tt>INFIX_CATEGORY_PARSER</tt>)", "md_docs_2API.html#autotoc_md32", null ],
          [ "Allocation Errors (<tt>INFIX_CATEGORY_ALLOCATION</tt>)", "md_docs_2API.html#autotoc_md33", null ],
          [ "ABI & Layout Errors (<tt>INFIX_CATEGORY_ABI</tt>)", "md_docs_2API.html#autotoc_md34", null ],
          [ "General & Library Errors", "md_docs_2API.html#autotoc_md35", null ]
        ] ]
      ] ],
      [ "3. Introspection API", "md_docs_2API.html#autotoc_md37", [
        [ "Library Version", "md_docs_2API.html#autotoc_md38", null ],
        [ "Getting Callable Code", "md_docs_2API.html#autotoc_md39", null ],
        [ "Inspecting Trampoline Properties", "md_docs_2API.html#autotoc_md40", null ],
        [ "Inspecting Type Properties", "md_docs_2API.html#autotoc_md41", null ]
      ] ],
      [ "4. Named Type Registry API", "md_docs_2API.html#autotoc_md43", [
        [ "Creation, Cloning, and Population", "md_docs_2API.html#autotoc_md44", null ],
        [ "Registry Introspection & Iteration", "md_docs_2API.html#autotoc_md45", null ]
      ] ],
      [ "5. Dynamic Library & Globals API", "md_docs_2API.html#autotoc_md47", null ],
      [ "6. Manual API (Advanced)", "md_docs_2API.html#autotoc_md49", [
        [ "Manual Trampoline Creation", "md_docs_2API.html#autotoc_md50", null ],
        [ "Trampoline Destruction", "md_docs_2API.html#autotoc_md51", null ],
        [ "Manual Type Creation", "md_docs_2API.html#autotoc_md52", null ]
      ] ],
      [ "7. Memory Management (Arenas)", "md_docs_2API.html#autotoc_md54", [
        [ "Custom Allocators", "md_docs_2API.html#autotoc_md55", null ]
      ] ]
    ] ],
    [ "The infix FFI Cookbook", "md_docs_2cookbook.html", [
      [ "Table of Contents", "md_docs_2cookbook.html#autotoc_md57", null ],
      [ "Chapter 1: The Basics (Forward Calls)", "md_docs_2cookbook.html#autotoc_md59", [
        [ "Recipe: Calling a Simple C Function", "md_docs_2cookbook.html#autotoc_md60", null ],
        [ "Recipe: Passing and Receiving Pointers", "md_docs_2cookbook.html#autotoc_md61", null ],
        [ "Recipe: Working with \"Out\" Parameters", "md_docs_2cookbook.html#autotoc_md62", null ],
        [ "Recipe: Working with Opaque Pointers (Incomplete Types)", "md_docs_2cookbook.html#autotoc_md63", null ]
      ] ],
      [ "</blockquote>", "md_docs_2cookbook.html#autotoc_md64", null ],
      [ "Chapter 2: Handling Complex Data Structures", "md_docs_2cookbook.html#autotoc_md65", [
        [ "Recipe: Small Structs Passed by Value", "md_docs_2cookbook.html#autotoc_md66", null ],
        [ "Recipe: Receiving a Struct from a Function", "md_docs_2cookbook.html#autotoc_md67", null ],
        [ "Recipe: Large Structs Passed by Reference", "md_docs_2cookbook.html#autotoc_md68", null ],
        [ "Recipe: Working with Packed Structs", "md_docs_2cookbook.html#autotoc_md69", null ],
        [ "Recipe: Working with Bitfields", "md_docs_2cookbook.html#autotoc_md70", null ],
        [ "Recipe: Working with Flexible Array Members (FAM)", "md_docs_2cookbook.html#autotoc_md71", null ],
        [ "Recipe: Working with Unions", "md_docs_2cookbook.html#autotoc_md72", null ],
        [ "Recipe: Working with Fixed-Size Arrays", "md_docs_2cookbook.html#autotoc_md73", null ],
        [ "Recipe: Advanced Named Types (Recursive & Forward-Declared)", "md_docs_2cookbook.html#autotoc_md74", null ],
        [ "Recipe: Working with Complex Numbers", "md_docs_2cookbook.html#autotoc_md75", null ],
        [ "Recipe: Working with SIMD Vectors", "md_docs_2cookbook.html#autotoc_md76", [
          [ "x86-64 (SSE, AVX, and AVX-512)", "md_docs_2cookbook.html#autotoc_md78", null ]
        ] ]
      ] ],
      [ "</blockquote>", "md_docs_2cookbook.html#autotoc_md79", null ],
      [ "</blockquote>", "md_docs_2cookbook.html#autotoc_md81", [
        [ "Recipe: Working with Enums", "md_docs_2cookbook.html#autotoc_md83", null ]
      ] ],
      [ "</blockquote>", "md_docs_2cookbook.html#autotoc_md84", null ],
      [ "Chapter 3: The Power of Callbacks (Reverse Calls)", "md_docs_2cookbook.html#autotoc_md85", [
        [ "Recipe: Creating a Type-Safe Callback for <tt>qsort</tt>", "md_docs_2cookbook.html#autotoc_md86", null ],
        [ "Recipe: Creating a Stateful Callback", "md_docs_2cookbook.html#autotoc_md87", null ]
      ] ],
      [ "</blockquote>", "md_docs_2cookbook.html#autotoc_md88", null ],
      [ "Chapter 4: Advanced Techniques", "md_docs_2cookbook.html#autotoc_md89", [
        [ "Recipe: Calling Variadic Functions like <tt>printf</tt>", "md_docs_2cookbook.html#autotoc_md90", null ],
        [ "Recipe: Receiving and Calling a Function Pointer", "md_docs_2cookbook.html#autotoc_md91", null ],
        [ "Recipe: Calling a Function Pointer from a Struct (V-Table Emulation)", "md_docs_2cookbook.html#autotoc_md92", null ],
        [ "Recipe: Handling <tt>long double</tt>", "md_docs_2cookbook.html#autotoc_md93", null ],
        [ "Recipe: Proving Reentrancy with Nested FFI Calls", "md_docs_2cookbook.html#autotoc_md94", null ],
        [ "Recipe: Proving Thread Safety", "md_docs_2cookbook.html#autotoc_md95", null ]
      ] ],
      [ "</blockquote>", "md_docs_2cookbook.html#autotoc_md96", null ],
      [ "Chapter 5: Interoperability with Other Languages", "md_docs_2cookbook.html#autotoc_md97", [
        [ "The Universal Principle: The C ABI", "md_docs_2cookbook.html#autotoc_md98", null ],
        [ "Recipe: Interfacing with a C++ Class (Directly)", "md_docs_2cookbook.html#autotoc_md99", null ],
        [ "Recipe: Interfacing with C++ Templates", "md_docs_2cookbook.html#autotoc_md100", null ],
        [ "The Pattern for Other Compiled Languages", "md_docs_2cookbook.html#autotoc_md101", [
          [ "Rust", "md_docs_2cookbook.html#autotoc_md102", null ],
          [ "Zig", "md_docs_2cookbook.html#autotoc_md103", null ],
          [ "Go", "md_docs_2cookbook.html#autotoc_md104", null ],
          [ "Swift", "md_docs_2cookbook.html#autotoc_md105", null ],
          [ "Dlang", "md_docs_2cookbook.html#autotoc_md106", null ],
          [ "Fortran", "md_docs_2cookbook.html#autotoc_md107", null ],
          [ "Assembly", "md_docs_2cookbook.html#autotoc_md108", null ]
        ] ],
        [ "Recipe: Handling Strings and Semantic Types (<tt>wchar_t</tt>, etc.)", "md_docs_2cookbook.html#autotoc_md109", null ],
        [ "Recipe: Calling C++ Virtual Functions (V-Table Emulation)", "md_docs_2cookbook.html#autotoc_md110", null ],
        [ "Recipe: Bridging C++ Callbacks (<tt>std::function</tt>) and Lambdas", "md_docs_2cookbook.html#autotoc_md111", null ]
      ] ],
      [ "Chapter 6: Dynamic Libraries & System Calls", "md_docs_2cookbook.html#autotoc_md112", [
        [ "Recipe: Calling Native System Libraries without Linking", "md_docs_2cookbook.html#autotoc_md113", null ],
        [ "Recipe: Reading and Writing Global Variables", "md_docs_2cookbook.html#autotoc_md114", [
          [ "Example 1: Simple Integer Variable", "md_docs_2cookbook.html#autotoc_md115", null ],
          [ "Example 2: Aggregate (Struct) Variable", "md_docs_2cookbook.html#autotoc_md116", null ]
        ] ],
        [ "Recipe: Handling Library Dependencies", "md_docs_2cookbook.html#autotoc_md117", null ]
      ] ],
      [ "</blockquote>", "md_docs_2cookbook.html#autotoc_md118", null ],
      [ "Chapter 7: Introspection for Data Marshalling", "md_docs_2cookbook.html#autotoc_md119", [
        [ "Recipe: Creating and Introspecting Semantic Aliases", "md_docs_2cookbook.html#autotoc_md120", null ],
        [ "Recipe: Dynamic Struct Marshalling with the Signature Parser", "md_docs_2cookbook.html#autotoc_md121", null ],
        [ "Recipe: Building a Signature String at Runtime", "md_docs_2cookbook.html#autotoc_md122", null ],
        [ "Recipe: Introspecting a Trampoline for a Wrapper", "md_docs_2cookbook.html#autotoc_md123", null ]
      ] ],
      [ "</blockquote>", "md_docs_2cookbook.html#autotoc_md124", null ],
      [ "Chapter 8: Performance & Memory Management", "md_docs_2cookbook.html#autotoc_md125", [
        [ "Best Practice: Caching Trampolines", "md_docs_2cookbook.html#autotoc_md126", null ],
        [ "Recipe: Using a Custom Arena for a Group of Types", "md_docs_2cookbook.html#autotoc_md127", null ],
        [ "Recipe: The Full Manual API Lifecycle (Types to Trampoline)", "md_docs_2cookbook.html#autotoc_md128", null ],
        [ "Recipe: Using Custom Memory Allocators", "md_docs_2cookbook.html#autotoc_md129", null ],
        [ "Recipe: Optimizing Memory with a Shared Arena", "md_docs_2cookbook.html#autotoc_md130", null ],
        [ "Recipe: Building a Dynamic Call Frame with an Arena", "md_docs_2cookbook.html#autotoc_md131", [
          [ "How It Works & Why It's Better", "md_docs_2cookbook.html#autotoc_md132", null ],
          [ "Advanced Optimization: Arena Resetting for Hot Loops", "md_docs_2cookbook.html#autotoc_md133", null ]
        ] ]
      ] ],
      [ "Chapter 9: Common Pitfalls & Troubleshooting", "md_docs_2cookbook.html#autotoc_md135", [
        [ "Recipe: Advanced Error Reporting for the Parser", "md_docs_2cookbook.html#autotoc_md136", null ],
        [ "Mistake: Passing a Value Instead of a Pointer in <tt>args[]</tt>", "md_docs_2cookbook.html#autotoc_md137", null ],
        [ "Mistake: <tt>infix</tt> Signature Mismatch", "md_docs_2cookbook.html#autotoc_md138", null ],
        [ "Pitfall: Function Pointer Syntax", "md_docs_2cookbook.html#autotoc_md139", null ]
      ] ],
      [ "Chapter 10: A Comparative Look: <tt>infix</tt> vs. <tt>libffi</tt> and <tt>dyncall</tt>", "md_docs_2cookbook.html#autotoc_md141", [
        [ "Scenario 1: Calling a Simple Function", "md_docs_2cookbook.html#autotoc_md142", [
          [ "The <tt>dyncall</tt> Approach", "md_docs_2cookbook.html#autotoc_md143", null ],
          [ "The <tt>libffi</tt> Approach", "md_docs_2cookbook.html#autotoc_md144", null ],
          [ "The <tt>infix</tt> Approach", "md_docs_2cookbook.html#autotoc_md145", null ]
        ] ],
        [ "Scenario 2: Calling a Function with a Struct", "md_docs_2cookbook.html#autotoc_md146", [
          [ "The <tt>dyncall</tt> Approach", "md_docs_2cookbook.html#autotoc_md147", null ],
          [ "The <tt>libffi</tt> Approach", "md_docs_2cookbook.html#autotoc_md148", null ],
          [ "The <tt>infix</tt> Approach", "md_docs_2cookbook.html#autotoc_md149", null ]
        ] ],
        [ "Scenario 3: Creating a Callback", "md_docs_2cookbook.html#autotoc_md150", [
          [ "The <tt>dyncall</tt> Approach", "md_docs_2cookbook.html#autotoc_md151", null ],
          [ "The <tt>libffi</tt> Approach", "md_docs_2cookbook.html#autotoc_md152", null ],
          [ "The <tt>infix</tt> Approach", "md_docs_2cookbook.html#autotoc_md153", null ]
        ] ],
        [ "Analysis and Takeaways", "md_docs_2cookbook.html#autotoc_md154", null ]
      ] ],
      [ "Chapter 11: Building Language Bindings", "md_docs_2cookbook.html#autotoc_md156", [
        [ "The Four Pillars of a Language Binding", "md_docs_2cookbook.html#autotoc_md157", null ],
        [ "Recipe: Porting a Python Binding from <tt>dyncall</tt> to <tt>infix</tt>", "md_docs_2cookbook.html#autotoc_md158", null ]
      ] ],
      [ "Chapter 12: High-Performance Language Bindings (Direct Marshalling)", "md_docs_2cookbook.html#autotoc_md159", null ],
      [ "Chapter 13: Handling Exceptions and Errors", "md_docs_2cookbook.html#autotoc_md161", [
        [ "Recipe: Establishing a Safe Exception Boundary", "md_docs_2cookbook.html#autotoc_md162", null ],
        [ "Recipe: Catching C++ Exceptions from Plain C", "md_docs_2cookbook.html#autotoc_md163", null ]
      ] ]
    ] ],
    [ "Building and Integrating infix", "md_docs_2INSTALL.html", [
      [ "Prerequisites", "md_docs_2INSTALL.html#autotoc_md165", null ],
      [ "1. The Easiest Way: Add <tt>infix</tt> Directly to Your Project", "md_docs_2INSTALL.html#autotoc_md167", null ],
      [ "</blockquote>", "md_docs_2INSTALL.html#autotoc_md168", null ],
      [ "2. Building <tt>infix</tt> as a Standalone Library (Optional)", "md_docs_2INSTALL.html#autotoc_md169", [
        [ "Using perl (Recommended)", "md_docs_2INSTALL.html#autotoc_md170", null ],
        [ "Using xmake", "md_docs_2INSTALL.html#autotoc_md171", null ],
        [ "Using CMake", "md_docs_2INSTALL.html#autotoc_md172", null ],
        [ "Using Makefiles", "md_docs_2INSTALL.html#autotoc_md173", null ],
        [ "Symbol Visibility", "md_docs_2INSTALL.html#autotoc_md174", null ],
        [ "Advanced Methods", "md_docs_2INSTALL.html#autotoc_md175", null ]
      ] ],
      [ "3. Linking Against a Pre-Built Library", "md_docs_2INSTALL.html#autotoc_md177", [
        [ "Using CMake with <tt>find_package</tt>", "md_docs_2INSTALL.html#autotoc_md178", null ],
        [ "Using pkg-config", "md_docs_2INSTALL.html#autotoc_md179", null ],
        [ "Using xmake", "md_docs_2INSTALL.html#autotoc_md180", null ],
        [ "Example: Visual Studio Code Configuration", "md_docs_2INSTALL.html#autotoc_md181", null ]
      ] ]
    ] ],
    [ "Architectural Notes", "md_docs_2internals.html", [
      [ "1. Core Design Philosophy", "md_docs_2internals.html#autotoc_md183", [
        [ "1.1 Guiding Principles", "md_docs_2internals.html#autotoc_md184", null ],
        [ "1.2 Key Architectural Decisions", "md_docs_2internals.html#autotoc_md185", [
          [ "The Unity Build", "md_docs_2internals.html#autotoc_md186", null ],
          [ "The Self-Contained Object Model", "md_docs_2internals.html#autotoc_md187", null ],
          [ "Arena-Based Manual API", "md_docs_2internals.html#autotoc_md188", null ],
          [ "A Dual-Model API for Callbacks and Closures", "md_docs_2internals.html#autotoc_md189", null ]
        ] ]
      ] ],
      [ "2. Architectural Overview", "md_docs_2internals.html#autotoc_md191", [
        [ "The Forward Trampoline Generation Pipeline", "md_docs_2internals.html#autotoc_md192", null ],
        [ "The Reverse Trampoline (Callback/Closure) Pipeline", "md_docs_2internals.html#autotoc_md193", null ],
        [ "The Direct Marshalling Pipeline", "md_docs_2internals.html#autotoc_md194", null ]
      ] ],
      [ "3. Security Features Deep Dive", "md_docs_2internals.html#autotoc_md196", [
        [ "3.1 Write XOR Execute (W^X)", "md_docs_2internals.html#autotoc_md197", null ],
        [ "3.2 Guard Pages and Read-Only Contexts", "md_docs_2internals.html#autotoc_md198", null ],
        [ "3.3 macOS JIT Hardening and the Entitlement Fallback", "md_docs_2internals.html#autotoc_md199", [
          [ "The Challenge: Hardened Runtimes on Apple Silicon", "md_docs_2internals.html#autotoc_md200", null ],
          [ "The <tt>infix</tt> Solution: Runtime Detection with Graceful Fallback", "md_docs_2internals.html#autotoc_md201", null ]
        ] ],
        [ "3.4 Fuzz Testing", "md_docs_2internals.html#autotoc_md202", null ],
        [ "3.5 API Input Hardening", "md_docs_2internals.html#autotoc_md203", null ]
      ] ],
      [ "4. Exception Handling Boundaries", "md_docs_2internals.html#autotoc_md205", [
        [ "4.1 Exception Propagation (Transparent Unwinding)", "md_docs_2internals.html#autotoc_md206", null ],
        [ "4.2 Safe Boundaries (<tt>infix_forward_create_safe</tt>)", "md_docs_2internals.html#autotoc_md207", null ]
      ] ],
      [ "5. ABI Internals", "md_docs_2internals.html#autotoc_md209", null ],
      [ "6. Maintainer's Debugging Guide", "md_docs_2internals.html#autotoc_md211", [
        [ "Method 1: Static Analysis with <tt>infix_dump_hex</tt>", "md_docs_2internals.html#autotoc_md212", null ],
        [ "Method 2: Live Debugging with GDB/LLDB", "md_docs_2internals.html#autotoc_md213", null ],
        [ "Useful Tools", "md_docs_2internals.html#autotoc_md214", null ]
      ] ]
    ] ],
    [ "Porting infix to a New ABI", "md_docs_2porting.html", [
      [ "Step 0: Research and Preparation", "md_docs_2porting.html#autotoc_md216", null ],
      [ "Step 1: Platform Detection (<tt>src/common/infix_config.h</tt>)", "md_docs_2porting.html#autotoc_md217", null ],
      [ "Step 2: Implement the ABI Specification", "md_docs_2porting.html#autotoc_md218", null ],
      [ "Step 3: Implement the Instruction Emitters", "md_docs_2porting.html#autotoc_md219", null ],
      [ "Step 4: Integrate the New ABI", "md_docs_2porting.html#autotoc_md220", null ],
      [ "Step 5: Testing", "md_docs_2porting.html#autotoc_md221", null ],
      [ "Step 6: Exception Handling Support (Optional but Recommended)", "md_docs_2porting.html#autotoc_md222", null ]
    ] ],
    [ "The infix Signature and Type System", "md_docs_2signatures.html", [
      [ "Part 2: The Signature Language Reference", "md_docs_2signatures.html#autotoc_md228", [
        [ "Part 1: Introduction", "md_docs_2signatures.html#autotoc_md224", [
          [ "1.1 The Challenge of Interoperability", "md_docs_2signatures.html#autotoc_md225", null ],
          [ "1.2 The Limitations of C Declarations", "md_docs_2signatures.html#autotoc_md226", null ],
          [ "1.3 Our Solution: A Human-First Signature System", "md_docs_2signatures.html#autotoc_md227", null ]
        ] ],
        [ "2.1 Primitives", "md_docs_2signatures.html#autotoc_md229", [
          [ "Tier 1: Abstract C Types", "md_docs_2signatures.html#autotoc_md230", null ],
          [ "Tier 2: Explicit Fixed-Width Types (Recommended)", "md_docs_2signatures.html#autotoc_md231", null ],
          [ "Tier 3: SIMD Vector Aliases", "md_docs_2signatures.html#autotoc_md232", null ]
        ] ],
        [ "2.2 Type Constructors and Composite Structures", "md_docs_2signatures.html#autotoc_md233", null ],
        [ "2.3 Syntax Showcase", "md_docs_2signatures.html#autotoc_md234", [
          [ "2.4 Bitfields and Flexible Arrays", "md_docs_2signatures.html#autotoc_md235", null ]
        ] ],
        [ "2.5 Scope and Namespaces", "md_docs_2signatures.html#autotoc_md236", null ],
        [ "2.6 Built-in Aliases vs. Registry Aliases", "md_docs_2signatures.html#autotoc_md237", [
          [ "Why this matters for Strings", "md_docs_2signatures.html#autotoc_md238", null ]
        ] ]
      ] ],
      [ "Part 3: The Named Type Registry", "md_docs_2signatures.html#autotoc_md240", [
        [ "Defining Types (<tt>infix_register_types</tt>)", "md_docs_2signatures.html#autotoc_md241", null ],
        [ "Using Named Types", "md_docs_2signatures.html#autotoc_md242", null ]
      ] ],
      [ "Part 4: Technical Specification", "md_docs_2signatures.html#autotoc_md244", null ]
    ] ],
    [ "Changelog", "md_CHANGELOG.html", [
      [ "<a href=\"https://github.com/sanko/infix/compare/v0.2.1...HEAD\"", "md_CHANGELOG.html#autotoc_md250", [
        [ "Added", "md_CHANGELOG.html#autotoc_md251", null ],
        [ "Fixed", "md_CHANGELOG.html#autotoc_md252", null ]
      ] ],
      [ "<a href=\"https://github.com/sanko/infix/compare/v0.2.0...v0.2.1\" >0.2.1</a> - 2026-08-04", "md_CHANGELOG.html#autotoc_md253", [
        [ "Fixed", "md_CHANGELOG.html#autotoc_md254", null ]
      ] ],
      [ "<a href=\"https://github.com/sanko/infix/compare/v0.1.7...v0.2.0\" >0.2.0</a> - 2026-08-03", "md_CHANGELOG.html#autotoc_md255", [
        [ "Added", "md_CHANGELOG.html#autotoc_md256", null ],
        [ "Changed", "md_CHANGELOG.html#autotoc_md257", null ],
        [ "Fixed", "md_CHANGELOG.html#autotoc_md258", null ]
      ] ],
      [ "<a href=\"https://github.com/sanko/infix/compare/v0.1.6...v0.1.7\" >0.1.7</a> - 2026-03-30", "md_CHANGELOG.html#autotoc_md259", [
        [ "Changed", "md_CHANGELOG.html#autotoc_md260", null ]
      ] ],
      [ "<a href=\"https://github.com/sanko/infix/compare/v0.1.5...v0.1.6\" >0.1.6</a> - 2026-02-14", "md_CHANGELOG.html#autotoc_md261", [
        [ "Added", "md_CHANGELOG.html#autotoc_md262", null ],
        [ "Fixed", "md_CHANGELOG.html#autotoc_md263", null ]
      ] ],
      [ "<a href=\"https://github.com/sanko/infix/compare/v0.1.4...v0.1.5\" >0.1.5</a> - 2026-02-06", "md_CHANGELOG.html#autotoc_md264", [
        [ "Added", "md_CHANGELOG.html#autotoc_md265", null ],
        [ "Changed", "md_CHANGELOG.html#autotoc_md266", null ],
        [ "Fixed", "md_CHANGELOG.html#autotoc_md267", null ]
      ] ],
      [ "<a href=\"https://github.com/sanko/infix/compare/v0.1.3...v0.1.4\" >0.1.4</a> - 2026-01-17", "md_CHANGELOG.html#autotoc_md268", [
        [ "Added", "md_CHANGELOG.html#autotoc_md269", null ],
        [ "Changed", "md_CHANGELOG.html#autotoc_md270", null ],
        [ "Fixed", "md_CHANGELOG.html#autotoc_md271", null ]
      ] ],
      [ "<a href=\"https://github.com/sanko/infix/compare/v0.1.2...v0.1.3\" >0.1.3</a> - 2025-12-19", "md_CHANGELOG.html#autotoc_md272", [
        [ "Changed", "md_CHANGELOG.html#autotoc_md273", null ],
        [ "Fixed", "md_CHANGELOG.html#autotoc_md274", null ]
      ] ],
      [ "<a href=\"https://github.com/sanko/infix/compare/v0.1.1...v0.1.2\" >0.1.2</a> - 2025-11-26", "md_CHANGELOG.html#autotoc_md275", [
        [ "Added", "md_CHANGELOG.html#autotoc_md276", null ],
        [ "Changed", "md_CHANGELOG.html#autotoc_md277", null ],
        [ "Fixed", "md_CHANGELOG.html#autotoc_md278", null ]
      ] ],
      [ "<a href=\"https://github.com/sanko/infix/compare/v0.1.0...v0.1.1\" >0.1.1</a> - 2025-11-01", "md_CHANGELOG.html#autotoc_md279", [
        [ "Added", "md_CHANGELOG.html#autotoc_md280", null ],
        [ "Changed", "md_CHANGELOG.html#autotoc_md281", null ],
        [ "Fixed", "md_CHANGELOG.html#autotoc_md282", null ]
      ] ],
      [ "<a href=\"https://github.com/sanko/infix/releases/tag/v0.1.0\" >0.1.0</a> - 2025-10-27", "md_CHANGELOG.html#autotoc_md283", [
        [ "Initial Public Release", "md_CHANGELOG.html#autotoc_md284", null ],
        [ "Added", "md_CHANGELOG.html#autotoc_md285", [
          [ "Security & Hardening", "md_CHANGELOG.html#autotoc_md286", null ],
          [ "Performance & Memory Management", "md_CHANGELOG.html#autotoc_md287", null ],
          [ "Platform Support", "md_CHANGELOG.html#autotoc_md288", null ]
        ] ]
      ] ]
    ] ],
    [ "Project Roadmap: infix FFI", "md_TODO.html", [
      [ "High Priority: Foundation & Stability", "md_TODO.html#autotoc_md290", null ],
      [ "Medium Priority: Expansion & Optimization", "md_TODO.html#autotoc_md291", null ],
      [ "Low Priority: Advanced Features & Polish", "md_TODO.html#autotoc_md292", null ],
      [ "High Priority: Foundation & Stability", "md_TODO.html#autotoc_md293", null ]
    ] ],
    [ "Security Policy", "md_SECURITY.html", [
      [ "Supported Versions", "md_SECURITY.html#autotoc_md295", null ],
      [ "Reporting a Vulnerability", "md_SECURITY.html#autotoc_md296", null ],
      [ "Security Model", "md_SECURITY.html#autotoc_md297", [
        [ "Mitigations", "md_SECURITY.html#autotoc_md298", [
          [ "1. W^X (Write XOR Execute) Memory Policy", "md_SECURITY.html#autotoc_md299", null ],
          [ "2. Use-After-Free Prevention (Guard Pages)", "md_SECURITY.html#autotoc_md300", null ],
          [ "3. Read-Only Context Hardening", "md_SECURITY.html#autotoc_md301", null ],
          [ "4. API Hardening Against Integer Overflows", "md_SECURITY.html#autotoc_md302", null ],
          [ "5. Continuous Security Validation (Fuzzing)", "md_SECURITY.html#autotoc_md303", null ]
        ] ]
      ] ]
    ] ],
    [ "Topics", "topics.html", "topics" ],
    [ "Classes", "annotated.html", [
      [ "Class List", "annotated.html", "annotated_dup" ],
      [ "Class Index", "classes.html", null ],
      [ "Class Members", "functions.html", [
        [ "All", "functions.html", "functions_dup" ],
        [ "Variables", "functions_vars.html", "functions_vars" ]
      ] ]
    ] ],
    [ "Files", "files.html", [
      [ "File List", "files.html", "files_dup" ],
      [ "File Members", "globals.html", [
        [ "All", "globals.html", "globals_dup" ],
        [ "Functions", "globals_func.html", "globals_func" ],
        [ "Variables", "globals_vars.html", null ],
        [ "Typedefs", "globals_type.html", null ],
        [ "Enumerations", "globals_enum.html", null ],
        [ "Enumerator", "globals_eval.html", "globals_eval" ],
        [ "Macros", "globals_defs.html", "globals_defs" ]
      ] ]
    ] ]
  ] ]
];

var NAVTREEINDEX =
[
"001__primitives_8c.html",
"301__primitives_8c.html#a67b44339c1ba7c1139e4ce7b02bcbfbe",
"821__threading__bare_8c.html",
"Ch04__Reentrancy_8c.html#a44e24e8a11367eb1b22c59dd485c9dda",
"abi__arm64__emitters_8c.html#a8b53fa5636791242490f7e89ea5a528d",
"abi__riscv64__emitters_8c.html#a2778f9b2a5c47d36afa7eb27d130875f",
"abi__x64__emitters_8h.html#a05540ee7d754daed3b36f4c5302841b6",
"emit__math_8c.html#afd00bc3d19840b1a621eea4deff8f96a",
"globals_func_s.html",
"group__memory__management.html#gadd947810fd44e245d2a0eff4a2f52c75",
"group__type__system.html#gga909e562b00e504aeceac698bd272f0caaf06a8a8b819b166236fabab3bf2bdcd4",
"md_docs_2cookbook.html#autotoc_md122",
"structMockObject.html#ad6699b58b928d3f991533966ae049630",
"structinfix__reverse__t.html#a5aeae580532069c4fecfb7a903382706"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';