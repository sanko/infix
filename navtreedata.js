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
    [ "infix: A JIT-Powered FFI Library for C", "index.html", "index" ],
    [ "The infix FFI Cookbook", "md_docs_2cookbook.html", [
      [ "Table of Contents", "md_docs_2cookbook.html#autotoc_md32", null ],
      [ "Chapter 1: The Basics (Forward Calls)", "md_docs_2cookbook.html#autotoc_md34", [
        [ "Recipe: Calling a Simple C Function", "md_docs_2cookbook.html#autotoc_md35", null ],
        [ "Recipe: Passing and Receiving Pointers", "md_docs_2cookbook.html#autotoc_md36", null ],
        [ "Recipe: Working with \"Out\" Parameters", "md_docs_2cookbook.html#autotoc_md37", null ],
        [ "Recipe: Working with Opaque Pointers (Incomplete Types)", "md_docs_2cookbook.html#autotoc_md38", null ]
      ] ],
      [ "</blockquote>", "md_docs_2cookbook.html#autotoc_md39", null ],
      [ "Chapter 2: Handling Complex Data Structures", "md_docs_2cookbook.html#autotoc_md40", [
        [ "Recipe: Small Structs Passed by Value", "md_docs_2cookbook.html#autotoc_md41", null ],
        [ "Recipe: Receiving a Struct from a Function", "md_docs_2cookbook.html#autotoc_md42", null ],
        [ "Recipe: Large Structs Passed by Reference", "md_docs_2cookbook.html#autotoc_md43", null ],
        [ "Recipe: Working with Packed Structs", "md_docs_2cookbook.html#autotoc_md44", null ],
        [ "Recipe: Working with Structs that Contain Bitfields", "md_docs_2cookbook.html#autotoc_md45", null ],
        [ "Recipe: Working with Unions", "md_docs_2cookbook.html#autotoc_md46", null ],
        [ "Recipe: Working with Fixed-Size Arrays", "md_docs_2cookbook.html#autotoc_md47", null ],
        [ "Recipe: Advanced Named Types (Recursive & Forward-Declared)", "md_docs_2cookbook.html#autotoc_md48", null ],
        [ "Recipe: Working with Complex Numbers", "md_docs_2cookbook.html#autotoc_md49", null ],
        [ "Recipe: Working with SIMD Vectors", "md_docs_2cookbook.html#autotoc_md50", [
          [ "x86-64 (SSE, AVX, and AVX-512)", "md_docs_2cookbook.html#autotoc_md52", null ]
        ] ]
      ] ],
      [ "</blockquote>", "md_docs_2cookbook.html#autotoc_md53", null ],
      [ "</blockquote>", "md_docs_2cookbook.html#autotoc_md55", [
        [ "Recipe: Working with Enums", "md_docs_2cookbook.html#autotoc_md57", null ]
      ] ],
      [ "</blockquote>", "md_docs_2cookbook.html#autotoc_md58", null ],
      [ "Chapter 3: The Power of Callbacks (Reverse Calls)", "md_docs_2cookbook.html#autotoc_md59", [
        [ "Recipe: Creating a Type-Safe Callback for <tt>qsort</tt>", "md_docs_2cookbook.html#autotoc_md60", null ],
        [ "Recipe: Creating a Stateful Callback", "md_docs_2cookbook.html#autotoc_md61", null ]
      ] ],
      [ "</blockquote>", "md_docs_2cookbook.html#autotoc_md62", null ],
      [ "Chapter 4: Advanced Techniques", "md_docs_2cookbook.html#autotoc_md63", [
        [ "Recipe: Calling Variadic Functions like <tt>printf</tt>", "md_docs_2cookbook.html#autotoc_md64", null ],
        [ "Recipe: Receiving and Calling a Function Pointer", "md_docs_2cookbook.html#autotoc_md65", null ],
        [ "Recipe: Calling a Function Pointer from a Struct (V-Table Emulation)", "md_docs_2cookbook.html#autotoc_md66", null ],
        [ "Recipe: Handling <tt>longdouble</tt>", "md_docs_2cookbook.html#autotoc_md67", null ],
        [ "Recipe: Proving Reentrancy with Nested FFI Calls", "md_docs_2cookbook.html#autotoc_md68", null ],
        [ "Recipe: Proving Thread Safety", "md_docs_2cookbook.html#autotoc_md69", null ]
      ] ],
      [ "</blockquote>", "md_docs_2cookbook.html#autotoc_md70", null ],
      [ "Chapter 5: Interoperability with Other Languages", "md_docs_2cookbook.html#autotoc_md71", [
        [ "The Universal Principle: The C ABI", "md_docs_2cookbook.html#autotoc_md72", null ],
        [ "Recipe: Interfacing with a C++ Class (Directly)", "md_docs_2cookbook.html#autotoc_md73", null ],
        [ "Recipe: Interfacing with C++ Templates", "md_docs_2cookbook.html#autotoc_md74", null ],
        [ "The Pattern for Other Compiled Languages", "md_docs_2cookbook.html#autotoc_md75", [
          [ "Rust", "md_docs_2cookbook.html#autotoc_md76", null ],
          [ "Zig", "md_docs_2cookbook.html#autotoc_md77", null ],
          [ "Go", "md_docs_2cookbook.html#autotoc_md78", null ],
          [ "Swift", "md_docs_2cookbook.html#autotoc_md79", null ],
          [ "Dlang", "md_docs_2cookbook.html#autotoc_md80", null ],
          [ "Fortran", "md_docs_2cookbook.html#autotoc_md81", null ],
          [ "Assembly", "md_docs_2cookbook.html#autotoc_md82", null ]
        ] ],
        [ "Recipe: Handling Strings and Semantic Types (<tt>wchar_t</tt>, etc.)", "md_docs_2cookbook.html#autotoc_md83", [
          [ "Step 1: Define Semantic Aliases in a Registry", "md_docs_2cookbook.html#autotoc_md84", null ],
          [ "Step 2: Use the Aliases in Your Signature", "md_docs_2cookbook.html#autotoc_md85", null ],
          [ "Step 3: Introspect with Semantic Awareness", "md_docs_2cookbook.html#autotoc_md86", null ]
        ] ],
        [ "Recipe: Calling C++ Virtual Functions (V-Table Emulation)", "md_docs_2cookbook.html#autotoc_md87", null ],
        [ "Recipe: Bridging C++ Callbacks (<tt>std::function</tt>) and Lambdas", "md_docs_2cookbook.html#autotoc_md88", null ]
      ] ],
      [ "Chapter 6: Dynamic Libraries & System Calls", "md_docs_2cookbook.html#autotoc_md89", [
        [ "Recipe: Calling Native System Libraries without Linking", "md_docs_2cookbook.html#autotoc_md90", null ],
        [ "Recipe: Reading and Writing Global Variables", "md_docs_2cookbook.html#autotoc_md91", [
          [ "Example 1: Simple Integer Variable", "md_docs_2cookbook.html#autotoc_md92", null ],
          [ "Example 2: Aggregate (Struct) Variable", "md_docs_2cookbook.html#autotoc_md93", null ]
        ] ],
        [ "Recipe: Handling Library Dependencies", "md_docs_2cookbook.html#autotoc_md94", null ]
      ] ],
      [ "</blockquote>", "md_docs_2cookbook.html#autotoc_md95", null ],
      [ "Chapter 7: Introspection for Data Marshalling", "md_docs_2cookbook.html#autotoc_md96", [
        [ "Recipe: Dynamic Struct Marshalling with the Signature Parser", "md_docs_2cookbook.html#autotoc_md97", null ],
        [ "Recipe: Building a Signature String at Runtime", "md_docs_2cookbook.html#autotoc_md98", null ],
        [ "Recipe: Introspecting a Trampoline for a Wrapper", "md_docs_2cookbook.html#autotoc_md99", null ]
      ] ],
      [ "</blockquote>", "md_docs_2cookbook.html#autotoc_md100", null ],
      [ "Chapter 8: Performance & Memory Management", "md_docs_2cookbook.html#autotoc_md101", [
        [ "Best Practice: Caching Trampolines", "md_docs_2cookbook.html#autotoc_md102", null ],
        [ "Recipe: Using a Custom Arena for a Group of Types", "md_docs_2cookbook.html#autotoc_md103", null ],
        [ "Recipe: The Full Manual API Lifecycle (Types to Trampoline)", "md_docs_2cookbook.html#autotoc_md104", null ],
        [ "Recipe: Using Custom Memory Allocators", "md_docs_2cookbook.html#autotoc_md105", null ],
        [ "Recipe: Building a Dynamic Call Frame with an Arena", "md_docs_2cookbook.html#autotoc_md106", [
          [ "How It Works & Why It's Better", "md_docs_2cookbook.html#autotoc_md107", null ],
          [ "Advanced Optimization: Arena Resetting for Hot Loops", "md_docs_2cookbook.html#autotoc_md108", null ]
        ] ]
      ] ],
      [ "Chapter 9: Common Pitfalls & Troubleshooting", "md_docs_2cookbook.html#autotoc_md110", [
        [ "Recipe: Advanced Error Reporting for the Parser", "md_docs_2cookbook.html#autotoc_md111", null ],
        [ "Mistake: Passing a Value Instead of a Pointer in <tt>args[]</tt>", "md_docs_2cookbook.html#autotoc_md112", null ],
        [ "Mistake: <tt>infix</tt> Signature Mismatch", "md_docs_2cookbook.html#autotoc_md113", null ],
        [ "Pitfall: Function Pointer Syntax", "md_docs_2cookbook.html#autotoc_md114", null ]
      ] ],
      [ "Chapter 10: A Comparative Look: <tt>infix</tt> vs. <tt>libffi</tt> and <tt>dyncall</tt>", "md_docs_2cookbook.html#autotoc_md116", [
        [ "Scenario 1: Calling a Simple Function", "md_docs_2cookbook.html#autotoc_md117", [
          [ "The <tt>dyncall</tt> Approach", "md_docs_2cookbook.html#autotoc_md118", null ],
          [ "The <tt>libffi</tt> Approach", "md_docs_2cookbook.html#autotoc_md119", null ],
          [ "The <tt>infix</tt> Approach", "md_docs_2cookbook.html#autotoc_md120", null ]
        ] ],
        [ "Scenario 2: Calling a Function with a Struct", "md_docs_2cookbook.html#autotoc_md121", [
          [ "The <tt>dyncall</tt> Approach", "md_docs_2cookbook.html#autotoc_md122", null ],
          [ "The <tt>libffi</tt> Approach", "md_docs_2cookbook.html#autotoc_md123", null ],
          [ "The <tt>infix</tt> Approach", "md_docs_2cookbook.html#autotoc_md124", null ]
        ] ],
        [ "Scenario 3: Creating a Callback", "md_docs_2cookbook.html#autotoc_md125", [
          [ "The <tt>dyncall</tt> Approach", "md_docs_2cookbook.html#autotoc_md126", null ],
          [ "The <tt>libffi</tt> Approach", "md_docs_2cookbook.html#autotoc_md127", null ],
          [ "The <tt>infix</tt> Approach", "md_docs_2cookbook.html#autotoc_md128", null ]
        ] ],
        [ "Analysis and Takeaways", "md_docs_2cookbook.html#autotoc_md129", null ]
      ] ],
      [ "Chapter 11: Building Language Bindings", "md_docs_2cookbook.html#autotoc_md131", [
        [ "The Four Pillars of a Language Binding", "md_docs_2cookbook.html#autotoc_md132", null ],
        [ "Recipe: Porting a Python Binding from <tt>dyncall</tt> to <tt>infix</tt>", "md_docs_2cookbook.html#autotoc_md133", null ]
      ] ]
    ] ],
    [ "Building and Integrating infix", "md_docs_2INSTALL.html", [
      [ "Prerequisites", "md_docs_2INSTALL.html#autotoc_md135", null ],
      [ "1. Building <tt>infix</tt> from Source", "md_docs_2INSTALL.html#autotoc_md137", [
        [ "Using xmake (Recommended)", "md_docs_2INSTALL.html#autotoc_md138", null ],
        [ "Using Perl", "md_docs_2INSTALL.html#autotoc_md139", null ],
        [ "Using CMake", "md_docs_2INSTALL.html#autotoc_md140", [
          [ "Using Makefiles", "md_docs_2INSTALL.html#autotoc_md145", [
            [ "GNU Make (Linux, macOS, BSDs)", "md_docs_2INSTALL.html#autotoc_md146", null ],
            [ "NMake (Windows with MSVC)", "md_docs_2INSTALL.html#autotoc_md148", null ]
          ] ],
          [ "Manual Compilation (Advanced)", "md_docs_2INSTALL.html#autotoc_md149", null ]
        ] ],
        [ "2. Integrating <tt>infix</tt> into Your Project", "md_docs_2INSTALL.html#autotoc_md151", [
          [ "Using CMake with <tt>find_package</tt>", "md_docs_2INSTALL.html#autotoc_md152", null ],
          [ "Using pkg-config", "md_docs_2INSTALL.html#autotoc_md153", null ],
          [ "Using xmake", "md_docs_2INSTALL.html#autotoc_md154", null ],
          [ "Using in Visual Studio Code", "md_docs_2INSTALL.html#autotoc_md155", [
            [ "Manual Integration into an Existing Project", "md_docs_2INSTALL.html#autotoc_md156", null ]
          ] ]
        ] ],
        [ "3. Packaging <tt>infix</tt> (For Maintainers)", "md_docs_2INSTALL.html#autotoc_md158", [
          [ "Linux Distributions (DEB/RPM)", "md_docs_2INSTALL.html#autotoc_md159", null ],
          [ "xmake Repository", "md_docs_2INSTALL.html#autotoc_md160", null ]
        ] ]
      ] ]
    ] ],
    [ "Architectural Notes", "md_docs_2internals.html", [
      [ "1. Core Design Philosophy", "md_docs_2internals.html#autotoc_md162", [
        [ "1.1 Guiding Principles", "md_docs_2internals.html#autotoc_md163", null ],
        [ "1.2 Key Architectural Decisions", "md_docs_2internals.html#autotoc_md164", [
          [ "The Unity Build", "md_docs_2internals.html#autotoc_md165", null ],
          [ "The Self-Contained Object Model", "md_docs_2internals.html#autotoc_md166", null ],
          [ "Arena-Based Manual API", "md_docs_2internals.html#autotoc_md167", null ],
          [ "A Dual-Model API for Callbacks and Closures", "md_docs_2internals.html#autotoc_md168", null ]
        ] ]
      ] ],
      [ "2. Architectural Overview", "md_docs_2internals.html#autotoc_md170", [
        [ "The Forward Trampoline Generation Pipeline", "md_docs_2internals.html#autotoc_md171", null ],
        [ "The Reverse Trampoline (Callback/Closure) Pipeline", "md_docs_2internals.html#autotoc_md172", null ]
      ] ],
      [ "3. Security Features Deep Dive", "md_docs_2internals.html#autotoc_md174", [
        [ "3.1 Write XOR Execute (W^X)", "md_docs_2internals.html#autotoc_md175", null ],
        [ "3.2 Guard Pages and Read-Only Contexts", "md_docs_2internals.html#autotoc_md176", null ],
        [ "3.3 macOS JIT Hardening and the Entitlement Fallback", "md_docs_2internals.html#autotoc_md177", [
          [ "The Challenge: Hardened Runtimes on Apple Silicon", "md_docs_2internals.html#autotoc_md178", null ],
          [ "The <tt>infix</tt> Solution: Runtime Detection with Graceful Fallback", "md_docs_2internals.html#autotoc_md179", null ]
        ] ],
        [ "3.4 Fuzz Testing", "md_docs_2internals.html#autotoc_md180", null ]
      ] ],
      [ "4. ABI Internals", "md_docs_2internals.html#autotoc_md182", null ],
      [ "5. Maintainer's Debugging Guide", "md_docs_2internals.html#autotoc_md184", [
        [ "Method 1: Static Analysis with <tt>infix_dump_hex</tt>", "md_docs_2internals.html#autotoc_md185", null ],
        [ "Method 2: Live Debugging with GDB/LLDB", "md_docs_2internals.html#autotoc_md186", null ],
        [ "Useful Tools", "md_docs_2internals.html#autotoc_md187", null ]
      ] ]
    ] ],
    [ "Porting infix to a New ABI", "md_docs_2porting.html", [
      [ "Step 0: Research and Preparation", "md_docs_2porting.html#autotoc_md189", null ],
      [ "Step 1: Platform Detection (<tt>src/common/infix_config.h</tt>)", "md_docs_2porting.html#autotoc_md190", null ],
      [ "Step 2: Implement the ABI Specification", "md_docs_2porting.html#autotoc_md191", null ],
      [ "Step 3: Implement the Instruction Emitters", "md_docs_2porting.html#autotoc_md192", null ],
      [ "Step 4: Integrate the New ABI", "md_docs_2porting.html#autotoc_md193", null ],
      [ "Step 5: Testing", "md_docs_2porting.html#autotoc_md194", null ]
    ] ],
    [ "The infix Signature and Type System", "md_docs_2signatures.html", [
      [ "Part 2: The Signature Language Reference", "md_docs_2signatures.html#autotoc_md200", [
        [ "Part 1: Introduction", "md_docs_2signatures.html#autotoc_md196", [
          [ "1.1 The Challenge of Interoperability", "md_docs_2signatures.html#autotoc_md197", null ],
          [ "1.2 The Limitations of C Declarations", "md_docs_2signatures.html#autotoc_md198", null ],
          [ "1.3 Our Solution: A Human-First Signature System", "md_docs_2signatures.html#autotoc_md199", null ]
        ] ],
        [ "2.1 Primitives", "md_docs_2signatures.html#autotoc_md201", [
          [ "Tier 1: Abstract C Types", "md_docs_2signatures.html#autotoc_md202", null ],
          [ "Tier 2: Explicit Fixed-Width Types (Recommended)", "md_docs_2signatures.html#autotoc_md203", null ],
          [ "Tier 3: SIMD Vector Aliases", "md_docs_2signatures.html#autotoc_md204", null ]
        ] ],
        [ "2.2 Type Constructors and Composite Structures", "md_docs_2signatures.html#autotoc_md205", null ],
        [ "2.3 Syntax Showcase", "md_docs_2signatures.html#autotoc_md206", null ]
      ] ],
      [ "Part 3: The Named Type Registry", "md_docs_2signatures.html#autotoc_md208", [
        [ "Defining Types (<tt>infix_register_types</tt>)", "md_docs_2signatures.html#autotoc_md209", null ],
        [ "Using Named Types", "md_docs_2signatures.html#autotoc_md210", null ]
      ] ],
      [ "Part 4: Technical Specification", "md_docs_2signatures.html#autotoc_md212", null ]
    ] ],
    [ "Changelog", "md_CHANGELOG.html", [
      [ "<a href=\"https://github.com/sanko/infix/compare/v0.1.0...HEAD\"", "md_CHANGELOG.html#autotoc_md218", [
        [ "Added", "md_CHANGELOG.html#autotoc_md219", null ],
        [ "Changed", "md_CHANGELOG.html#autotoc_md220", null ],
        [ "Fixed", "md_CHANGELOG.html#autotoc_md221", null ]
      ] ],
      [ "<a href=\"https://github.com/sanko/infix/releases/tag/v0.1.0\" >0.1.0</a> - 2025-10-27", "md_CHANGELOG.html#autotoc_md222", [
        [ "Initial Public Release", "md_CHANGELOG.html#autotoc_md223", null ],
        [ "Added", "md_CHANGELOG.html#autotoc_md224", [
          [ "Security & Hardening", "md_CHANGELOG.html#autotoc_md225", null ],
          [ "Performance & Memory Management", "md_CHANGELOG.html#autotoc_md226", null ],
          [ "Platform Support", "md_CHANGELOG.html#autotoc_md227", null ]
        ] ]
      ] ]
    ] ],
    [ "Project Roadmap: infix FFI", "md_TODO.html", [
      [ "High Priority: Foundation & Stability", "md_TODO.html#autotoc_md229", null ],
      [ "Medium Priority: Expansion & Optimization", "md_TODO.html#autotoc_md230", null ],
      [ "Low Priority: Advanced Features & Polish", "md_TODO.html#autotoc_md231", null ]
    ] ],
    [ "Security Policy", "md_SECURITY.html", [
      [ "Supported Versions", "md_SECURITY.html#autotoc_md233", null ],
      [ "Reporting a Vulnerability", "md_SECURITY.html#autotoc_md234", null ],
      [ "Security Model", "md_SECURITY.html#autotoc_md235", [
        [ "Mitigations", "md_SECURITY.html#autotoc_md236", [
          [ "1. W^X (Write XOR Execute) Memory Policy", "md_SECURITY.html#autotoc_md237", null ],
          [ "2. Use-After-Free Prevention (Guard Pages)", "md_SECURITY.html#autotoc_md238", null ],
          [ "3. Read-Only Context Hardening", "md_SECURITY.html#autotoc_md239", null ],
          [ "4. API Hardening Against Integer Overflows", "md_SECURITY.html#autotoc_md240", null ],
          [ "5. Continuous Security Validation (Fuzzing)", "md_SECURITY.html#autotoc_md241", null ]
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
        [ "Enumerator", "globals_eval.html", null ],
        [ "Macros", "globals_defs.html", null ]
      ] ]
    ] ]
  ] ]
];

var NAVTREEINDEX =
[
"001__primitives_8c.html",
"304__reverse__call__types_8c.html#a2f303d7c7dc0e9919104b83d9af8c9db",
"Ch04__Rec03__VTableCStyle_8c.html#a204fd2a6866501ac1cd3d7bb85634832",
"abi__sysv__x64_8c.html#a85f7abdfc580bdbd531c2a8a84490629",
"executor_8c_source.html",
"group__high__level__api.html#gaefbba96a3cadf0e38ba54f1ff7cb93b1",
"group__type__system.html#gga909e562b00e504aeceac698bd272f0caa1f6e7b58d6fa04a5885655155ef73c8a",
"md_docs_2cookbook.html#autotoc_md68",
"structinfix__reverse__abi__spec.html"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';