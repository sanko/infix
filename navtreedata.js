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
    [ "The <tt>infix</tt> FFI Cookbook", "md_docs_2cookbook.html", [
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
        [ "<strong>Recipe: Working with Enums</strong>", "md_docs_2cookbook.html#autotoc_md54", null ]
      ] ],
      [ "Chapter 3: The Power of Callbacks (Reverse Calls)", "md_docs_2cookbook.html#autotoc_md56", [
        [ "Recipe: Creating a Stateless Callback for <tt>qsort</tt>", "md_docs_2cookbook.html#autotoc_md57", null ],
        [ "Recipe: Creating a Stateful Callback", "md_docs_2cookbook.html#autotoc_md58", null ]
      ] ],
      [ "Chapter 4: Advanced Techniques", "md_docs_2cookbook.html#autotoc_md60", [
        [ "Recipe: Calling Variadic Functions like <tt>printf</tt>", "md_docs_2cookbook.html#autotoc_md61", null ],
        [ "Recipe: Receiving and Calling a Function Pointer", "md_docs_2cookbook.html#autotoc_md62", null ],
        [ "Recipe: Calling a Function Pointer from a Struct (V-Table Emulation)", "md_docs_2cookbook.html#autotoc_md63", null ],
        [ "<strong>Recipe: Handling <tt>long double</tt></strong>", "md_docs_2cookbook.html#autotoc_md64", null ],
        [ "Recipe: Proving Reentrancy with Nested FFI Calls", "md_docs_2cookbook.html#autotoc_md65", null ],
        [ "<strong>Recipe: Proving Thread Safety</strong>", "md_docs_2cookbook.html#autotoc_md66", null ]
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
        [ "<strong>Recipe: Using Custom Memory Allocators</strong>", "md_docs_2cookbook.html#autotoc_md95", null ]
      ] ],
      [ "Chapter 9: Common Pitfalls & Troubleshooting", "md_docs_2cookbook.html#autotoc_md97", [
        [ "Mistake: Passing a Value Instead of a Pointer in <tt>args[]</tt>", "md_docs_2cookbook.html#autotoc_md98", null ],
        [ "Mistake: <tt>infix</tt> Signature Mismatch", "md_docs_2cookbook.html#autotoc_md99", null ],
        [ "Pitfall: Function Pointer Syntax", "md_docs_2cookbook.html#autotoc_md100", null ]
      ] ],
      [ "Chapter 10: A Comparative Look: <tt>infix</tt> vs. <tt>libffi</tt> and <tt>dyncall</tt>", "md_docs_2cookbook.html#autotoc_md102", [
        [ "Scenario 1: Calling a Simple Function", "md_docs_2cookbook.html#autotoc_md103", [
          [ "The <tt>dyncall</tt> Approach", "md_docs_2cookbook.html#autotoc_md104", null ],
          [ "The <tt>libffi</tt> Approach", "md_docs_2cookbook.html#autotoc_md105", null ],
          [ "The <tt>infix</tt> Approach", "md_docs_2cookbook.html#autotoc_md106", null ]
        ] ],
        [ "Scenario 2: Calling a Function with a Struct", "md_docs_2cookbook.html#autotoc_md107", [
          [ "The <tt>dyncall</tt> Approach", "md_docs_2cookbook.html#autotoc_md108", null ],
          [ "The <tt>libffi</tt> Approach", "md_docs_2cookbook.html#autotoc_md109", null ],
          [ "The <tt>infix</tt> Approach", "md_docs_2cookbook.html#autotoc_md110", null ]
        ] ],
        [ "Scenario 3: Creating a Callback", "md_docs_2cookbook.html#autotoc_md111", [
          [ "The <tt>dyncall</tt> Approach", "md_docs_2cookbook.html#autotoc_md112", null ],
          [ "The <tt>libffi</tt> Approach", "md_docs_2cookbook.html#autotoc_md113", null ],
          [ "The <tt>infix</tt> Approach", "md_docs_2cookbook.html#autotoc_md114", null ]
        ] ],
        [ "Analysis and Takeaways", "md_docs_2cookbook.html#autotoc_md115", null ]
      ] ],
      [ "Chapter 11: Building Language Bindings", "md_docs_2cookbook.html#autotoc_md117", [
        [ "The Four Pillars of a Language Binding", "md_docs_2cookbook.html#autotoc_md118", null ],
        [ "Recipe: Porting a Python Binding from <tt>dyncall</tt> to <tt>infix</tt>", "md_docs_2cookbook.html#autotoc_md119", null ]
      ] ]
    ] ],
    [ "infix Internals and Architecture", "md_docs_2internals.html", [
      [ "1. Core Design Philosophy", "md_docs_2internals.html#autotoc_md121", [
        [ "1.1 Guiding Principles", "md_docs_2internals.html#autotoc_md122", null ],
        [ "1.2 Key Architectural Decisions", "md_docs_2internals.html#autotoc_md123", [
          [ "The Unity Build", "md_docs_2internals.html#autotoc_md124", null ],
          [ "The Self-Contained Object Model", "md_docs_2internals.html#autotoc_md125", null ],
          [ "Arena-Based Manual API", "md_docs_2internals.html#autotoc_md126", null ],
          [ "Universal Context for Callbacks", "md_docs_2internals.html#autotoc_md127", null ]
        ] ]
      ] ],
      [ "2. Architectural Overview", "md_docs_2internals.html#autotoc_md129", [
        [ "The Trampoline Generation Pipeline", "md_docs_2internals.html#autotoc_md130", null ]
      ] ],
      [ "3. Security Features Deep Dive", "md_docs_2internals.html#autotoc_md132", [
        [ "3.1 Write XOR Execute (W^X)", "md_docs_2internals.html#autotoc_md133", null ],
        [ "3.2 Guard Pages and Read-Only Contexts", "md_docs_2internals.html#autotoc_md134", null ],
        [ "3.3 macOS JIT Hardening and the Entitlement Fallback", "md_docs_2internals.html#autotoc_md135", [
          [ "The Challenge: Hardened Runtimes on Apple Silicon", "md_docs_2internals.html#autotoc_md136", null ],
          [ "The <tt>infix</tt> Solution: Runtime Detection with Graceful Fallback", "md_docs_2internals.html#autotoc_md137", null ]
        ] ],
        [ "3.4 Fuzz Testing", "md_docs_2internals.html#autotoc_md138", null ]
      ] ],
      [ "4. ABI Internals", "md_docs_2internals.html#autotoc_md140", null ],
      [ "5. Maintainer's Debugging Guide", "md_docs_2internals.html#autotoc_md142", [
        [ "Method 1: Static Analysis with <tt>infix_dump_hex</tt>", "md_docs_2internals.html#autotoc_md143", null ],
        [ "Method 2: Live Debugging with GDB/LLDB", "md_docs_2internals.html#autotoc_md144", null ],
        [ "Useful Tools", "md_docs_2internals.html#autotoc_md145", null ]
      ] ]
    ] ],
    [ "Porting <tt>infix</tt> to a New Platform", "md_docs_2porting.html", [
      [ "Step 0: Research and Preparation", "md_docs_2porting.html#autotoc_md147", null ],
      [ "Step 1: Platform Detection (<tt>src/common/infix_config.h</tt>)", "md_docs_2porting.html#autotoc_md148", null ],
      [ "Step 2: Implement the ABI Specification", "md_docs_2porting.html#autotoc_md149", null ],
      [ "Step 3: Implement the Instruction Emitters", "md_docs_2porting.html#autotoc_md150", null ],
      [ "Step 4: Integrate the New ABI", "md_docs_2porting.html#autotoc_md151", null ],
      [ "Step 5: Testing", "md_docs_2porting.html#autotoc_md152", null ]
    ] ],
    [ "The infix Signature and Type System", "md_docs_2signatures.html", [
      [ "Part 2: The Signature Language Reference", "md_docs_2signatures.html#autotoc_md158", [
        [ "Part 1: Introduction", "md_docs_2signatures.html#autotoc_md154", [
          [ "1.1 The Challenge of Interoperability", "md_docs_2signatures.html#autotoc_md155", null ],
          [ "1.2 The Limitations of C Declarations", "md_docs_2signatures.html#autotoc_md156", null ],
          [ "1.3 Our Solution: A Human-First Signature System", "md_docs_2signatures.html#autotoc_md157", null ]
        ] ],
        [ "2.1 Primitives", "md_docs_2signatures.html#autotoc_md159", [
          [ "Tier 1: Abstract C Types", "md_docs_2signatures.html#autotoc_md160", null ],
          [ "Tier 2: Explicit Fixed-Width Types (Recommended)", "md_docs_2signatures.html#autotoc_md161", null ]
        ] ],
        [ "2.2 Type Constructors and Composite Structures", "md_docs_2signatures.html#autotoc_md162", null ],
        [ "2.3 Syntax Showcase", "md_docs_2signatures.html#autotoc_md163", null ]
      ] ],
      [ "Part 3: The Named Type Registry", "md_docs_2signatures.html#autotoc_md165", [
        [ "Defining Types (<tt>infix_register_types</tt>)", "md_docs_2signatures.html#autotoc_md166", null ],
        [ "Using Named Types", "md_docs_2signatures.html#autotoc_md167", null ]
      ] ],
      [ "Part 4: Technical Specification", "md_docs_2signatures.html#autotoc_md169", null ]
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
    ] ],
    [ "Examples", "examples.html", "examples" ]
  ] ]
];

var NAVTREEINDEX =
[
"_2home_2runner_2work_2infix_2infix_2include_2infix_2infix_8h-example.html",
"abi__x64__common_8h.html#aa0462ce602242494cfb714c3e286853cafd6b7890692fd70bc41505877be9e2ab",
"group__memory__management.html",
"md_docs_2internals.html#autotoc_md122"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';