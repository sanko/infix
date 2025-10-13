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
      [ "Table of Contents", "md_docs_2cookbook.html#autotoc_md36", null ],
      [ "Chapter 1: The Basics (Forward Calls)", "md_docs_2cookbook.html#autotoc_md38", [
        [ "Recipe: Calling a Simple C Function", "md_docs_2cookbook.html#autotoc_md39", null ],
        [ "Recipe: Passing and Receiving Pointers", "md_docs_2cookbook.html#autotoc_md40", null ],
        [ "Recipe: Working with \"Out\" Parameters", "md_docs_2cookbook.html#autotoc_md41", null ],
        [ "Recipe: Working with Opaque Pointers (Incomplete Types)", "md_docs_2cookbook.html#autotoc_md42", null ]
      ] ],
      [ "Chapter 2: Handling Complex Data Structures", "md_docs_2cookbook.html#autotoc_md44", [
        [ "Recipe: Small Structs Passed by Value", "md_docs_2cookbook.html#autotoc_md45", null ],
        [ "Recipe: Receiving a Struct from a Function", "md_docs_2cookbook.html#autotoc_md46", null ],
        [ "Recipe: Large Structs Passed by Reference", "md_docs_2cookbook.html#autotoc_md47", null ],
        [ "Recipe: Working with Packed Structs", "md_docs_2cookbook.html#autotoc_md48", null ],
        [ "Recipe: Working with Structs that Contain Bitfields", "md_docs_2cookbook.html#autotoc_md49", null ],
        [ "Recipe: Working with Unions", "md_docs_2cookbook.html#autotoc_md50", null ],
        [ "Recipe: Working with Fixed-Size Arrays", "md_docs_2cookbook.html#autotoc_md51", null ],
        [ "Recipe: Working with Complex Numbers", "md_docs_2cookbook.html#autotoc_md52", null ],
        [ "Recipe: Working with SIMD Vectors", "md_docs_2cookbook.html#autotoc_md53", null ],
        [ "Recipe: Working with Enums", "md_docs_2cookbook.html#autotoc_md54", null ]
      ] ],
      [ "Chapter 3: The Power of Callbacks (Reverse Calls)", "md_docs_2cookbook.html#autotoc_md56", [
        [ "Recipe: Creating a Stateless Callback for <tt>qsort</tt>", "md_docs_2cookbook.html#autotoc_md57", null ],
        [ "Recipe: Creating a Stateful Callback", "md_docs_2cookbook.html#autotoc_md58", null ]
      ] ],
      [ "Chapter 4: Advanced Techniques", "md_docs_2cookbook.html#autotoc_md60", [
        [ "Recipe: Calling Variadic Functions like <tt>printf</tt>", "md_docs_2cookbook.html#autotoc_md61", null ],
        [ "Recipe: Receiving and Calling a Function Pointer", "md_docs_2cookbook.html#autotoc_md62", null ],
        [ "Recipe: Calling a Function Pointer from a Struct (V-Table Emulation)", "md_docs_2cookbook.html#autotoc_md63", null ],
        [ "Recipe: Handling <tt>longdouble</tt>", "md_docs_2cookbook.html#autotoc_md64", null ],
        [ "Recipe: Proving Reentrancy with Nested FFI Calls", "md_docs_2cookbook.html#autotoc_md65", null ],
        [ "Recipe: Proving Thread Safety", "md_docs_2cookbook.html#autotoc_md66", null ]
      ] ],
      [ "Chapter 5: Interoperability with Other Languages", "md_docs_2cookbook.html#autotoc_md68", [
        [ "The Universal Principle: The C ABI", "md_docs_2cookbook.html#autotoc_md69", null ],
        [ "Recipe: Interfacing with a C++ Class (Directly)", "md_docs_2cookbook.html#autotoc_md70", null ],
        [ "Recipe: Interfacing with C++ Templates", "md_docs_2cookbook.html#autotoc_md71", null ],
        [ "The Pattern for Other Compiled Languages", "md_docs_2cookbook.html#autotoc_md72", [
          [ "Rust", "md_docs_2cookbook.html#autotoc_md73", null ],
          [ "Zig", "md_docs_2cookbook.html#autotoc_md74", null ],
          [ "Go", "md_docs_2cookbook.html#autotoc_md75", null ],
          [ "Swift", "md_docs_2cookbook.html#autotoc_md76", null ],
          [ "Dlang", "md_docs_2cookbook.html#autotoc_md77", null ],
          [ "Fortran", "md_docs_2cookbook.html#autotoc_md78", null ],
          [ "Assembly", "md_docs_2cookbook.html#autotoc_md79", null ]
        ] ]
      ] ],
      [ "Chapter 6: Dynamic Libraries & System Calls", "md_docs_2cookbook.html#autotoc_md80", [
        [ "Recipe: Calling Native System Libraries without Linking", "md_docs_2cookbook.html#autotoc_md81", null ],
        [ "Recipe: Reading and Writing Global Variables", "md_docs_2cookbook.html#autotoc_md82", [
          [ "Example 1: Simple Integer Variable", "md_docs_2cookbook.html#autotoc_md83", null ],
          [ "Example 2: Aggregate (Struct) Variable", "md_docs_2cookbook.html#autotoc_md84", null ]
        ] ],
        [ "Recipe: Handling Library Dependencies", "md_docs_2cookbook.html#autotoc_md85", null ]
      ] ],
      [ "Chapter 7: Introspection for Data Marshalling", "md_docs_2cookbook.html#autotoc_md87", [
        [ "Recipe: Dynamic Struct Marshalling with the Signature Parser", "md_docs_2cookbook.html#autotoc_md88", null ],
        [ "Recipe: Building a Signature String at Runtime", "md_docs_2cookbook.html#autotoc_md89", null ],
        [ "Recipe: Introspecting a Trampoline for a Wrapper", "md_docs_2cookbook.html#autotoc_md90", null ]
      ] ],
      [ "Chapter 8: Performance & Memory Management", "md_docs_2cookbook.html#autotoc_md92", [
        [ "Best Practice: Caching Trampolines", "md_docs_2cookbook.html#autotoc_md93", null ],
        [ "Recipe: Using a Custom Arena for a Group of Types", "md_docs_2cookbook.html#autotoc_md94", null ],
        [ "Recipe: Using Custom Memory Allocators", "md_docs_2cookbook.html#autotoc_md95", null ],
        [ "<strong>Recipe: Building a Dynamic Call Frame with an Arena</strong>", "md_docs_2cookbook.html#autotoc_md96", [
          [ "How It Works & Why It's Better", "md_docs_2cookbook.html#autotoc_md97", null ],
          [ "Advanced Optimization: Arena Resetting for Hot Loops", "md_docs_2cookbook.html#autotoc_md98", null ]
        ] ]
      ] ],
      [ "Chapter 9: Common Pitfalls & Troubleshooting", "md_docs_2cookbook.html#autotoc_md100", [
        [ "Mistake: Passing a Value Instead of a Pointer in <tt>args[]</tt>", "md_docs_2cookbook.html#autotoc_md101", null ],
        [ "Mistake: <tt>infix</tt> Signature Mismatch", "md_docs_2cookbook.html#autotoc_md102", null ],
        [ "Pitfall: Function Pointer Syntax", "md_docs_2cookbook.html#autotoc_md103", null ]
      ] ],
      [ "Chapter 10: A Comparative Look: <tt>infix</tt> vs. <tt>libffi</tt> and <tt>dyncall</tt>", "md_docs_2cookbook.html#autotoc_md105", [
        [ "Scenario 1: Calling a Simple Function", "md_docs_2cookbook.html#autotoc_md106", [
          [ "The <tt>dyncall</tt> Approach", "md_docs_2cookbook.html#autotoc_md107", null ],
          [ "The <tt>libffi</tt> Approach", "md_docs_2cookbook.html#autotoc_md108", null ],
          [ "The <tt>infix</tt> Approach", "md_docs_2cookbook.html#autotoc_md109", null ]
        ] ],
        [ "Scenario 2: Calling a Function with a Struct", "md_docs_2cookbook.html#autotoc_md110", [
          [ "The <tt>dyncall</tt> Approach", "md_docs_2cookbook.html#autotoc_md111", null ],
          [ "The <tt>libffi</tt> Approach", "md_docs_2cookbook.html#autotoc_md112", null ],
          [ "The <tt>infix</tt> Approach", "md_docs_2cookbook.html#autotoc_md113", null ]
        ] ],
        [ "Scenario 3: Creating a Callback", "md_docs_2cookbook.html#autotoc_md114", [
          [ "The <tt>dyncall</tt> Approach", "md_docs_2cookbook.html#autotoc_md115", null ],
          [ "The <tt>libffi</tt> Approach", "md_docs_2cookbook.html#autotoc_md116", null ],
          [ "The <tt>infix</tt> Approach", "md_docs_2cookbook.html#autotoc_md117", null ]
        ] ],
        [ "Analysis and Takeaways", "md_docs_2cookbook.html#autotoc_md118", null ]
      ] ],
      [ "Chapter 11: Building Language Bindings", "md_docs_2cookbook.html#autotoc_md120", [
        [ "The Four Pillars of a Language Binding", "md_docs_2cookbook.html#autotoc_md121", null ],
        [ "Recipe: Porting a Python Binding from <tt>dyncall</tt> to <tt>infix</tt>", "md_docs_2cookbook.html#autotoc_md122", null ]
      ] ]
    ] ],
    [ "Building and Integrating infix", "md_docs_2INSTALL.html", [
      [ "Prerequisites", "md_docs_2INSTALL.html#autotoc_md124", null ],
      [ "1. Building <tt>infix</tt> from Source", "md_docs_2INSTALL.html#autotoc_md126", [
        [ "Using xmake (Recommended)", "md_docs_2INSTALL.html#autotoc_md127", null ],
        [ "Using Perl", "md_docs_2INSTALL.html#autotoc_md128", null ],
        [ "Using CMake", "md_docs_2INSTALL.html#autotoc_md129", [
          [ "Using Makefiles", "md_docs_2INSTALL.html#autotoc_md134", [
            [ "GNU Make (Linux, macOS, BSDs)", "md_docs_2INSTALL.html#autotoc_md135", null ],
            [ "NMake (Windows with MSVC)", "md_docs_2INSTALL.html#autotoc_md137", null ]
          ] ],
          [ "Manual Compilation (Advanced)", "md_docs_2INSTALL.html#autotoc_md138", null ]
        ] ],
        [ "2. Integrating <tt>infix</tt> into Your Project", "md_docs_2INSTALL.html#autotoc_md140", [
          [ "Using CMake with <tt>find_package</tt>", "md_docs_2INSTALL.html#autotoc_md141", null ],
          [ "Using pkg-config", "md_docs_2INSTALL.html#autotoc_md142", null ],
          [ "Using xmake", "md_docs_2INSTALL.html#autotoc_md143", null ],
          [ "Using in Visual Studio Code", "md_docs_2INSTALL.html#autotoc_md144", [
            [ "Manual Integration into an Existing Project", "md_docs_2INSTALL.html#autotoc_md145", null ]
          ] ]
        ] ],
        [ "3. Packaging <tt>infix</tt> (For Maintainers)", "md_docs_2INSTALL.html#autotoc_md147", [
          [ "Linux Distributions (DEB/RPM)", "md_docs_2INSTALL.html#autotoc_md148", null ],
          [ "xmake Repository", "md_docs_2INSTALL.html#autotoc_md149", null ]
        ] ]
      ] ]
    ] ],
    [ "Architectural Notes", "md_docs_2internals.html", [
      [ "1. Core Design Philosophy", "md_docs_2internals.html#autotoc_md151", [
        [ "1.1 Guiding Principles", "md_docs_2internals.html#autotoc_md152", null ],
        [ "1.2 Key Architectural Decisions", "md_docs_2internals.html#autotoc_md153", [
          [ "The Unity Build", "md_docs_2internals.html#autotoc_md154", null ],
          [ "The Self-Contained Object Model", "md_docs_2internals.html#autotoc_md155", null ],
          [ "Arena-Based Manual API", "md_docs_2internals.html#autotoc_md156", null ],
          [ "Universal Context for Callbacks", "md_docs_2internals.html#autotoc_md157", null ]
        ] ]
      ] ],
      [ "2. Architectural Overview", "md_docs_2internals.html#autotoc_md159", [
        [ "The Trampoline Generation Pipeline", "md_docs_2internals.html#autotoc_md160", null ]
      ] ],
      [ "3. Security Features Deep Dive", "md_docs_2internals.html#autotoc_md162", [
        [ "3.1 Write XOR Execute (W^X)", "md_docs_2internals.html#autotoc_md163", null ],
        [ "3.2 Guard Pages and Read-Only Contexts", "md_docs_2internals.html#autotoc_md164", null ],
        [ "3.3 macOS JIT Hardening and the Entitlement Fallback", "md_docs_2internals.html#autotoc_md165", [
          [ "The Challenge: Hardened Runtimes on Apple Silicon", "md_docs_2internals.html#autotoc_md166", null ],
          [ "The <tt>infix</tt> Solution: Runtime Detection with Graceful Fallback", "md_docs_2internals.html#autotoc_md167", null ]
        ] ],
        [ "3.4 Fuzz Testing", "md_docs_2internals.html#autotoc_md168", null ]
      ] ],
      [ "4. ABI Internals", "md_docs_2internals.html#autotoc_md170", null ],
      [ "5. Maintainer's Debugging Guide", "md_docs_2internals.html#autotoc_md172", [
        [ "Method 1: Static Analysis with <tt>infix_dump_hex</tt>", "md_docs_2internals.html#autotoc_md173", null ],
        [ "Method 2: Live Debugging with GDB/LLDB", "md_docs_2internals.html#autotoc_md174", null ],
        [ "Useful Tools", "md_docs_2internals.html#autotoc_md175", null ]
      ] ]
    ] ],
    [ "Porting infix to a New ABI", "md_docs_2porting.html", [
      [ "Step 0: Research and Preparation", "md_docs_2porting.html#autotoc_md177", null ],
      [ "Step 1: Platform Detection (<tt>src/common/infix_config.h</tt>)", "md_docs_2porting.html#autotoc_md178", null ],
      [ "Step 2: Implement the ABI Specification", "md_docs_2porting.html#autotoc_md179", null ],
      [ "Step 3: Implement the Instruction Emitters", "md_docs_2porting.html#autotoc_md180", null ],
      [ "Step 4: Integrate the New ABI", "md_docs_2porting.html#autotoc_md181", null ],
      [ "Step 5: Testing", "md_docs_2porting.html#autotoc_md182", null ]
    ] ],
    [ "The infix Signature and Type System", "md_docs_2signatures.html", [
      [ "Part 2: The Signature Language Reference", "md_docs_2signatures.html#autotoc_md188", [
        [ "Part 1: Introduction", "md_docs_2signatures.html#autotoc_md184", [
          [ "1.1 The Challenge of Interoperability", "md_docs_2signatures.html#autotoc_md185", null ],
          [ "1.2 The Limitations of C Declarations", "md_docs_2signatures.html#autotoc_md186", null ],
          [ "1.3 Our Solution: A Human-First Signature System", "md_docs_2signatures.html#autotoc_md187", null ]
        ] ],
        [ "2.1 Primitives", "md_docs_2signatures.html#autotoc_md189", [
          [ "Tier 1: Abstract C Types", "md_docs_2signatures.html#autotoc_md190", null ],
          [ "Tier 2: Explicit Fixed-Width Types (Recommended)", "md_docs_2signatures.html#autotoc_md191", null ]
        ] ],
        [ "2.2 Type Constructors and Composite Structures", "md_docs_2signatures.html#autotoc_md192", null ],
        [ "2.3 Syntax Showcase", "md_docs_2signatures.html#autotoc_md193", null ]
      ] ],
      [ "Part 3: The Named Type Registry", "md_docs_2signatures.html#autotoc_md195", [
        [ "Defining Types (<tt>infix_register_types</tt>)", "md_docs_2signatures.html#autotoc_md196", null ],
        [ "Using Named Types", "md_docs_2signatures.html#autotoc_md197", null ]
      ] ],
      [ "Part 4: Technical Specification", "md_docs_2signatures.html#autotoc_md199", null ]
    ] ],
    [ "Changelog", "md_CHANGELOG.html", [
      [ "<a href=\"https://github.com/sanko/infix/compare/v0.1.0...HEAD\"", "md_CHANGELOG.html#autotoc_md206", [
        [ "Added", "md_CHANGELOG.html#autotoc_md207", null ]
      ] ]
    ] ],
    [ "Topics", "topics.html", "topics" ],
    [ "Classes", "annotated.html", [
      [ "Class List", "annotated.html", "annotated_dup" ],
      [ "Class Index", "classes.html", null ],
      [ "Class Members", "functions.html", [
        [ "All", "functions.html", null ],
        [ "Variables", "functions_vars.html", null ]
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
"401__large__stack_8c.html#af17c47557820689b297102a239ba009b",
"abi__arm64__common_8h.html#a84639a49e91a2455fb857495a718e3beac61d78e3a51ddaca6fd5c96453974272",
"compat__c23_8h.html#a375e33770fc0a906c61d85025ab11b70",
"group__type__system.html#ggaad7a91cc786d4cec1dbbddb5d7b165b7a192c803c42b18a1e8f76a0faf02fd5c6",
"signature_8c.html#a72477cb1bc3a1a22e006a8563e61a5cd"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';