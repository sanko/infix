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
  [ "infix FFI Library", "index.html", [
    [ "Changelog", "md_CHANGELOG.html", [
      [ "[Unreleased]", "md_CHANGELOG.html#autotoc_md1", [
        [ "Added", "md_CHANGELOG.html#autotoc_md2", null ]
      ] ]
    ] ],
    [ "Contributor Code of Conduct", "md_CODE__OF__CONDUCT.html", [
      [ "Our Pledge", "md_CODE__OF__CONDUCT.html#autotoc_md4", null ],
      [ "Our Standards", "md_CODE__OF__CONDUCT.html#autotoc_md5", null ],
      [ "Our Responsibilities", "md_CODE__OF__CONDUCT.html#autotoc_md6", null ],
      [ "Scope", "md_CODE__OF__CONDUCT.html#autotoc_md7", null ],
      [ "Enforcement", "md_CODE__OF__CONDUCT.html#autotoc_md8", null ],
      [ "Attribution", "md_CODE__OF__CONDUCT.html#autotoc_md9", null ]
    ] ],
    [ "Contributing to the infix FFI Library", "md_CONTRIBUTING.html", [
      [ "Code of Conduct", "md_CONTRIBUTING.html#autotoc_md11", null ],
      [ "How to Contribute", "md_CONTRIBUTING.html#autotoc_md12", null ]
    ] ],
    [ "The <tt>infix</tt> FFI Cookbook", "md_docs_2cookbook.html", [
      [ "Table of Contents", "md_docs_2cookbook.html#autotoc_md16", null ],
      [ "Chapter 1: The Basics (Forward Calls)", "md_docs_2cookbook.html#autotoc_md18", [
        [ "Recipe: Calling a Simple C Function", "md_docs_2cookbook.html#autotoc_md19", null ],
        [ "Recipe: Passing and Receiving Pointers", "md_docs_2cookbook.html#autotoc_md20", null ],
        [ "Recipe: Working with Opaque Pointers (Incomplete Types)", "md_docs_2cookbook.html#autotoc_md21", null ]
      ] ],
      [ "Chapter 2: Handling Complex Data Structures", "md_docs_2cookbook.html#autotoc_md23", [
        [ "Recipe: Small Structs Passed by Value", "md_docs_2cookbook.html#autotoc_md24", null ],
        [ "Recipe: Receiving a Struct from a Function", "md_docs_2cookbook.html#autotoc_md25", null ],
        [ "Recipe: Large Structs Passed by Reference", "md_docs_2cookbook.html#autotoc_md26", null ],
        [ "Recipe: Working with Packed Structs", "md_docs_2cookbook.html#autotoc_md27", null ],
        [ "Recipe: Working with Unions", "md_docs_2cookbook.html#autotoc_md28", null ],
        [ "Recipe: Working with Fixed-Size Arrays", "md_docs_2cookbook.html#autotoc_md29", null ],
        [ "Recipe: Working with Complex Numbers", "md_docs_2cookbook.html#autotoc_md30", null ],
        [ "Recipe: Working with SIMD Vectors", "md_docs_2cookbook.html#autotoc_md31", null ]
      ] ],
      [ "Chapter 3: The Power of Callbacks (Reverse Calls)", "md_docs_2cookbook.html#autotoc_md33", [
        [ "Recipe: Creating a Stateless Callback for <tt>qsort</tt>", "md_docs_2cookbook.html#autotoc_md34", null ],
        [ "Recipe: Creating a Stateful Callback", "md_docs_2cookbook.html#autotoc_md35", null ]
      ] ],
      [ "Chapter 4: Advanced Techniques", "md_docs_2cookbook.html#autotoc_md37", [
        [ "Recipe: Calling Variadic Functions like <tt>printf</tt>", "md_docs_2cookbook.html#autotoc_md38", null ],
        [ "Recipe: Receiving and Calling a Function Pointer", "md_docs_2cookbook.html#autotoc_md39", null ],
        [ "Recipe: Proving Reentrancy with Nested FFI Calls", "md_docs_2cookbook.html#autotoc_md40", null ]
      ] ],
      [ "Chapter 5: Interoperability with Other Languages", "md_docs_2cookbook.html#autotoc_md42", [
        [ "The Universal Principle: The C ABI", "md_docs_2cookbook.html#autotoc_md43", null ],
        [ "Recipe: Interfacing with a C++ Class (Directly)", "md_docs_2cookbook.html#autotoc_md44", null ],
        [ "Recipe: Interfacing with C++ Templates", "md_docs_2cookbook.html#autotoc_md45", null ],
        [ "The Pattern for Other Compiled Languages", "md_docs_2cookbook.html#autotoc_md46", [
          [ "Rust", "md_docs_2cookbook.html#autotoc_md47", null ],
          [ "Zig", "md_docs_2cookbook.html#autotoc_md48", null ],
          [ "Go", "md_docs_2cookbook.html#autotoc_md49", null ],
          [ "Swift", "md_docs_2cookbook.html#autotoc_md50", null ],
          [ "Dlang", "md_docs_2cookbook.html#autotoc_md51", null ],
          [ "Fortran", "md_docs_2cookbook.html#autotoc_md52", null ],
          [ "Assembly", "md_docs_2cookbook.html#autotoc_md53", null ]
        ] ]
      ] ],
      [ "Chapter 6: Dynamic Libraries & System Calls", "md_docs_2cookbook.html#autotoc_md55", [
        [ "Recipe: Calling Native System Libraries without Linking", "md_docs_2cookbook.html#autotoc_md56", null ],
        [ "Recipe: Reading and Writing Global Variables", "md_docs_2cookbook.html#autotoc_md57", [
          [ "Example 1: Simple Integer Variable", "md_docs_2cookbook.html#autotoc_md58", null ],
          [ "Example 2: Aggregate (Struct) Variable", "md_docs_2cookbook.html#autotoc_md59", null ]
        ] ],
        [ "Recipe: Handling Library Dependencies", "md_docs_2cookbook.html#autotoc_md60", null ]
      ] ],
      [ "Chapter 7: Introspection for Data Marshalling", "md_docs_2cookbook.html#autotoc_md62", [
        [ "Recipe: Dynamic Struct Marshalling with the Signature Parser", "md_docs_2cookbook.html#autotoc_md63", null ],
        [ "Recipe: Introspecting a Trampoline for a Wrapper", "md_docs_2cookbook.html#autotoc_md64", null ]
      ] ],
      [ "Chapter 8: Performance & Memory Management", "md_docs_2cookbook.html#autotoc_md66", [
        [ "Best Practice: Caching Trampolines", "md_docs_2cookbook.html#autotoc_md67", null ],
        [ "Recipe: Using a Custom Arena for a Group of Types", "md_docs_2cookbook.html#autotoc_md68", null ]
      ] ],
      [ "Chapter 9: Common Pitfalls & Troubleshooting", "md_docs_2cookbook.html#autotoc_md70", [
        [ "Mistake: Passing a Value Instead of a Pointer in <tt>args[]</tt>", "md_docs_2cookbook.html#autotoc_md71", null ],
        [ "Mistake: <tt>infix</tt> Signature Mismatch", "md_docs_2cookbook.html#autotoc_md72", null ],
        [ "Pitfall: Function Pointer Syntax", "md_docs_2cookbook.html#autotoc_md73", null ]
      ] ],
      [ "Chapter 10: A Comparative Look: <tt>infix</tt> vs. <tt>libffi</tt> and <tt>dyncall</tt>", "md_docs_2cookbook.html#autotoc_md75", [
        [ "Scenario 1: Calling a Simple Function", "md_docs_2cookbook.html#autotoc_md76", [
          [ "The <tt>dyncall</tt> Approach", "md_docs_2cookbook.html#autotoc_md77", null ],
          [ "The <tt>libffi</tt> Approach", "md_docs_2cookbook.html#autotoc_md78", null ],
          [ "The <tt>infix</tt> Approach", "md_docs_2cookbook.html#autotoc_md79", null ]
        ] ],
        [ "Scenario 2: Calling a Function with a Struct", "md_docs_2cookbook.html#autotoc_md80", [
          [ "The <tt>dyncall</tt> Approach", "md_docs_2cookbook.html#autotoc_md81", null ],
          [ "The <tt>libffi</tt> Approach", "md_docs_2cookbook.html#autotoc_md82", null ],
          [ "The <tt>infix</tt> Approach", "md_docs_2cookbook.html#autotoc_md83", null ]
        ] ],
        [ "Scenario 3: Creating a Callback", "md_docs_2cookbook.html#autotoc_md84", [
          [ "The <tt>dyncall</tt> Approach", "md_docs_2cookbook.html#autotoc_md85", null ],
          [ "The <tt>libffi</tt> Approach", "md_docs_2cookbook.html#autotoc_md86", null ],
          [ "The <tt>infix</tt> Approach", "md_docs_2cookbook.html#autotoc_md87", null ]
        ] ],
        [ "Analysis and Takeaways", "md_docs_2cookbook.html#autotoc_md88", null ]
      ] ],
      [ "Chapter 11: Building Language Bindings", "md_docs_2cookbook.html#autotoc_md90", [
        [ "The Four Pillars of a Language Binding", "md_docs_2cookbook.html#autotoc_md91", null ],
        [ "Recipe: Porting a Python Binding from <tt>dyncall</tt> to <tt>infix</tt>", "md_docs_2cookbook.html#autotoc_md92", null ]
      ] ]
    ] ],
    [ "Infix Internals and Architecture", "md_docs_2internals.html", [
      [ "1. Core Design Philosophy", "md_docs_2internals.html#autotoc_md94", [
        [ "1.1 Guiding Principles", "md_docs_2internals.html#autotoc_md95", null ],
        [ "1.2 Key Architectural Decisions", "md_docs_2internals.html#autotoc_md96", [
          [ "The Unity Build", "md_docs_2internals.html#autotoc_md97", null ],
          [ "The Self-Contained Object Model", "md_docs_2internals.html#autotoc_md98", null ],
          [ "Arena-Based Manual API", "md_docs_2internals.html#autotoc_md99", null ],
          [ "Universal Context for Callbacks", "md_docs_2internals.html#autotoc_md100", null ]
        ] ]
      ] ],
      [ "2. Architectural Overview", "md_docs_2internals.html#autotoc_md102", [
        [ "The Trampoline Generation Pipeline", "md_docs_2internals.html#autotoc_md103", null ]
      ] ],
      [ "3. Security Features Deep Dive", "md_docs_2internals.html#autotoc_md105", [
        [ "3.1 Write XOR Execute (W^X)", "md_docs_2internals.html#autotoc_md106", null ],
        [ "3.2 Guard Pages and Read-Only Contexts", "md_docs_2internals.html#autotoc_md107", null ],
        [ "3.3 Fuzz Testing", "md_docs_2internals.html#autotoc_md108", null ]
      ] ],
      [ "4. ABI Internals", "md_docs_2internals.html#autotoc_md110", null ],
      [ "5. Maintainer's Debugging Guide", "md_docs_2internals.html#autotoc_md112", [
        [ "Method 1: Static Analysis with <tt>infix_dump_hex</tt>", "md_docs_2internals.html#autotoc_md113", null ],
        [ "Method 2: Live Debugging with GDB/LLDB", "md_docs_2internals.html#autotoc_md114", null ],
        [ "Useful Tools", "md_docs_2internals.html#autotoc_md115", null ]
      ] ],
      [ "External ABI Documentation", "md_docs_2internals.html#autotoc_md116", null ]
    ] ],
    [ "Porting <tt>infix</tt> to a New Platform", "md_docs_2porting.html", [
      [ "Step 0: Research and Preparation", "md_docs_2porting.html#autotoc_md118", null ],
      [ "Step 1: Platform Detection (<tt>src/common/infix_config.h</tt>)", "md_docs_2porting.html#autotoc_md119", null ],
      [ "Step 2: Implement the ABI Specification", "md_docs_2porting.html#autotoc_md120", null ],
      [ "Step 3: Implement the Instruction Emitters", "md_docs_2porting.html#autotoc_md121", null ],
      [ "Step 4: Integrate the New ABI", "md_docs_2porting.html#autotoc_md122", null ],
      [ "Step 5: Testing", "md_docs_2porting.html#autotoc_md123", null ]
    ] ],
    [ "The Infix Signature and Type System", "md_docs_2signatures.html", [
      [ "Part 2: The Signature Language Reference", "md_docs_2signatures.html#autotoc_md129", [
        [ "Part 1: Introduction", "md_docs_2signatures.html#autotoc_md125", [
          [ "1.1 The Challenge of Interoperability", "md_docs_2signatures.html#autotoc_md126", null ],
          [ "1.2 The Limitations of C Declarations", "md_docs_2signatures.html#autotoc_md127", null ],
          [ "1.3 Our Solution: A Human-First Signature System", "md_docs_2signatures.html#autotoc_md128", null ]
        ] ],
        [ "2.1 Primitives", "md_docs_2signatures.html#autotoc_md130", [
          [ "Tier 1: Abstract C Types", "md_docs_2signatures.html#autotoc_md131", null ],
          [ "Tier 2: Explicit Fixed-Width Types (Recommended)", "md_docs_2signatures.html#autotoc_md132", null ]
        ] ],
        [ "2.2 Type Constructors and Composite Structures", "md_docs_2signatures.html#autotoc_md133", null ],
        [ "2.3 Syntax Showcase", "md_docs_2signatures.html#autotoc_md134", null ]
      ] ],
      [ "Part 3: The Named Type Registry", "md_docs_2signatures.html#autotoc_md136", [
        [ "Defining Types (<tt>infix_register_types</tt>)", "md_docs_2signatures.html#autotoc_md137", null ],
        [ "Using Named Types", "md_docs_2signatures.html#autotoc_md138", null ]
      ] ],
      [ "Part 4: Technical Specification", "md_docs_2signatures.html#autotoc_md140", null ]
    ] ],
    [ "Customization", "md_doxygen-awesome-css_2docs_2customization.html", [
      [ "CSS-Variables", "md_doxygen-awesome-css_2docs_2customization.html#autotoc_md146", [
        [ "Setup", "md_doxygen-awesome-css_2docs_2customization.html#autotoc_md147", null ],
        [ "Available variables", "md_doxygen-awesome-css_2docs_2customization.html#autotoc_md148", null ]
      ] ],
      [ "Doxygen generator", "md_doxygen-awesome-css_2docs_2customization.html#autotoc_md149", null ],
      [ "Share your customizations", "md_doxygen-awesome-css_2docs_2customization.html#autotoc_md150", null ]
    ] ],
    [ "Extensions", "md_doxygen-awesome-css_2docs_2extensions.html", [
      [ "Dark Mode Toggle", "md_doxygen-awesome-css_2docs_2extensions.html#extension-dark-mode-toggle", [
        [ "Installation", "md_doxygen-awesome-css_2docs_2extensions.html#autotoc_md152", null ],
        [ "Customizing", "md_doxygen-awesome-css_2docs_2extensions.html#autotoc_md153", null ]
      ] ],
      [ "Fragment Copy Button", "md_doxygen-awesome-css_2docs_2extensions.html#extension-copy-button", [
        [ "Installation", "md_doxygen-awesome-css_2docs_2extensions.html#autotoc_md154", null ],
        [ "Customizing", "md_doxygen-awesome-css_2docs_2extensions.html#autotoc_md155", null ]
      ] ],
      [ "Paragraph Linking", "md_doxygen-awesome-css_2docs_2extensions.html#extension-para", [
        [ "Installation", "md_doxygen-awesome-css_2docs_2extensions.html#autotoc_md156", null ],
        [ "Customizing", "md_doxygen-awesome-css_2docs_2extensions.html#autotoc_md157", null ]
      ] ],
      [ "Interactive TOC", "md_doxygen-awesome-css_2docs_2extensions.html#extension-toc", [
        [ "Installation", "md_doxygen-awesome-css_2docs_2extensions.html#autotoc_md158", null ],
        [ "Customizing", "md_doxygen-awesome-css_2docs_2extensions.html#autotoc_md159", null ]
      ] ],
      [ "Tabs", "md_doxygen-awesome-css_2docs_2extensions.html#extension-tabs", [
        [ "Installation", "md_doxygen-awesome-css_2docs_2extensions.html#autotoc_md160", null ],
        [ "Usage", "md_doxygen-awesome-css_2docs_2extensions.html#autotoc_md161", null ]
      ] ],
      [ "Page Navigation", "md_doxygen-awesome-css_2docs_2extensions.html#extension-page-navigation", [
        [ "Installation", "md_doxygen-awesome-css_2docs_2extensions.html#autotoc_md162", null ],
        [ "Usage", "md_doxygen-awesome-css_2docs_2extensions.html#autotoc_md163", null ]
      ] ]
    ] ],
    [ "Tips & Tricks", "md_doxygen-awesome-css_2docs_2tricks.html", [
      [ "Diagrams with Graphviz", "md_doxygen-awesome-css_2docs_2tricks.html#tricks-graphviz", null ],
      [ "Disable Dark Mode", "md_doxygen-awesome-css_2docs_2tricks.html#tricks-darkmode", null ],
      [ "Choosing Sidebar Width", "md_doxygen-awesome-css_2docs_2tricks.html#tricks-sidebar", null ],
      [ "Formatting Tables", "md_doxygen-awesome-css_2docs_2tricks.html#tricks-tables", [
        [ "Centering", "md_doxygen-awesome-css_2docs_2tricks.html#autotoc_md165", null ],
        [ "Full Width", "md_doxygen-awesome-css_2docs_2tricks.html#autotoc_md166", null ],
        [ "Buttons", "md_doxygen-awesome-css_2docs_2tricks.html#autotoc_md167", null ],
        [ "Bordered Images", "md_doxygen-awesome-css_2docs_2tricks.html#autotoc_md168", null ]
      ] ]
    ] ],
    [ "Doxygen Awesome", "md_doxygen-awesome-css_2README.html", [
      [ "Motivation", "md_doxygen-awesome-css_2README.html#autotoc_md170", null ],
      [ "Features", "md_doxygen-awesome-css_2README.html#autotoc_md171", null ],
      [ "Examples", "md_doxygen-awesome-css_2README.html#autotoc_md172", null ],
      [ "Installation", "md_doxygen-awesome-css_2README.html#autotoc_md173", [
        [ "Git submodule", "md_doxygen-awesome-css_2README.html#autotoc_md174", null ],
        [ "CMake with FetchContent", "md_doxygen-awesome-css_2README.html#autotoc_md175", null ],
        [ "npm/xpm dependency", "md_doxygen-awesome-css_2README.html#autotoc_md176", null ],
        [ "System-wide", "md_doxygen-awesome-css_2README.html#autotoc_md177", null ],
        [ "Choosing a layout", "md_doxygen-awesome-css_2README.html#autotoc_md178", null ],
        [ "Further installation instructions", "md_doxygen-awesome-css_2README.html#autotoc_md179", null ]
      ] ],
      [ "Browser support", "md_doxygen-awesome-css_2README.html#autotoc_md180", null ],
      [ "Credits", "md_doxygen-awesome-css_2README.html#autotoc_md181", null ]
    ] ],
    [ "Building and Integrating <tt>infix</tt>", "md_INSTALL.html", [
      [ "Prerequisites", "md_INSTALL.html#autotoc_md184", null ],
      [ "1. Building <tt>infix</tt> from Source", "md_INSTALL.html#autotoc_md186", [
        [ "Using xmake (Recommended)", "md_INSTALL.html#autotoc_md187", null ],
        [ "Using Perl", "md_INSTALL.html#autotoc_md188", null ],
        [ "Using CMake", "md_INSTALL.html#autotoc_md189", [
          [ "Using Makefiles", "md_INSTALL.html#autotoc_md194", [
            [ "GNU Make (Linux, macOS, BSDs)", "md_INSTALL.html#autotoc_md195", null ],
            [ "NMake (Windows with MSVC)", "md_INSTALL.html#autotoc_md197", null ]
          ] ],
          [ "Manual Compilation (Advanced)", "md_INSTALL.html#autotoc_md198", null ]
        ] ],
        [ "2. Integrating <tt>infix</tt> into Your Project", "md_INSTALL.html#autotoc_md200", [
          [ "Using CMake with <tt>find_package</tt>", "md_INSTALL.html#autotoc_md201", null ],
          [ "Using pkg-config", "md_INSTALL.html#autotoc_md202", null ],
          [ "Using xmake", "md_INSTALL.html#autotoc_md203", null ],
          [ "Using in Visual Studio Code", "md_INSTALL.html#autotoc_md204", [
            [ "Manual Integration into an Existing Project", "md_INSTALL.html#autotoc_md205", null ]
          ] ]
        ] ],
        [ "3. Packaging <tt>infix</tt> (For Maintainers)", "md_INSTALL.html#autotoc_md207", [
          [ "Linux Distributions (DEB/RPM)", "md_INSTALL.html#autotoc_md208", null ],
          [ "xmake Repository", "md_INSTALL.html#autotoc_md209", null ]
        ] ]
      ] ]
    ] ],
    [ "<tt>infix</tt>: A JIT-Powered FFI Library for C", "md_README.html", [
      [ "Who is this for?", "md_README.html#autotoc_md211", null ],
      [ "Key Features", "md_README.html#autotoc_md212", null ],
      [ "Getting Started", "md_README.html#autotoc_md213", [
        [ "Prerequisites", "md_README.html#autotoc_md214", null ],
        [ "Building the Library", "md_README.html#autotoc_md215", null ],
        [ "Integrating into Your Project", "md_README.html#autotoc_md216", null ],
        [ "Quick Start: A 60-Second Example", "md_README.html#autotoc_md217", null ]
      ] ],
      [ "Usage Guide", "md_README.html#autotoc_md218", [
        [ "Part 1: The Signature Language", "md_README.html#autotoc_md219", null ],
        [ "Part 2: Common Recipes", "md_README.html#autotoc_md220", [
          [ "Forward Call (Calling C from your code)", "md_README.html#autotoc_md221", null ],
          [ "Reverse Call (Creating a C callback)", "md_README.html#autotoc_md222", null ],
          [ "Using the Named Type Registry", "md_README.html#autotoc_md223", null ],
          [ "Reading Global Variables from a Shared Library", "md_README.html#autotoc_md224", null ]
        ] ],
        [ "Part 3: The Manual C API (Advanced)", "md_README.html#autotoc_md225", null ],
        [ "Powerful Introspection for Dynamic Data Marshalling", "md_README.html#autotoc_md226", null ],
        [ "Error Handling", "md_README.html#autotoc_md227", null ]
      ] ],
      [ "API Reference", "md_README.html#autotoc_md228", [
        [ "Named Type Registry (<tt>registry_api</tt>)", "md_README.html#autotoc_md229", null ],
        [ "High-Level Signature API (<tt>high_level_api</tt>)", "md_README.html#autotoc_md230", null ],
        [ "Dynamic Library & Globals API (<tt>exports_api</tt>)", "md_README.html#autotoc_md231", null ],
        [ "Manual API (<tt>manual_api</tt>)", "md_README.html#autotoc_md232", null ],
        [ "Type System (<tt>type_system</tt>)", "md_README.html#autotoc_md233", null ],
        [ "Memory Management (<tt>memory_management</tt>)", "md_README.html#autotoc_md234", null ],
        [ "Introspection API (<tt>introspection_api</tt>)", "md_README.html#autotoc_md235", null ],
        [ "Error Handling API (<tt>error_api</tt>)", "md_README.html#autotoc_md236", null ]
      ] ],
      [ "Supported Platforms", "md_README.html#autotoc_md237", null ],
      [ "Building and Integrating", "md_README.html#autotoc_md238", null ],
      [ "Contributing", "md_README.html#autotoc_md239", null ],
      [ "Learn More", "md_README.html#autotoc_md240", null ],
      [ "License & Legal", "md_README.html#autotoc_md241", [
        [ "Code License", "md_README.html#autotoc_md242", null ],
        [ "Documentation License", "md_README.html#autotoc_md243", null ]
      ] ]
    ] ],
    [ "Security Policy", "md_SECURITY.html", [
      [ "Supported Versions", "md_SECURITY.html#autotoc_md245", null ],
      [ "Reporting a Vulnerability", "md_SECURITY.html#autotoc_md246", null ],
      [ "Security Model", "md_SECURITY.html#autotoc_md247", [
        [ "Mitigations", "md_SECURITY.html#autotoc_md248", [
          [ "1. W^X (Write XOR Execute) Memory Policy", "md_SECURITY.html#autotoc_md249", null ],
          [ "2. Use-After-Free Prevention (Guard Pages)", "md_SECURITY.html#autotoc_md250", null ],
          [ "3. Read-Only Context Hardening", "md_SECURITY.html#autotoc_md251", null ],
          [ "4. API Hardening Against Integer Overflows", "md_SECURITY.html#autotoc_md252", null ],
          [ "5. Continuous Security Validation (Fuzzing)", "md_SECURITY.html#autotoc_md253", null ]
        ] ]
      ] ]
    ] ],
    [ "<strong>Project Roadmap: infix FFI</strong>", "md_TODO.html", [
      [ "<strong>High Priority: Foundation & Stability</strong>", "md_TODO.html#autotoc_md256", null ],
      [ "<strong>Medium Priority: Expansion & Optimization</strong>", "md_TODO.html#autotoc_md257", null ],
      [ "<strong>Low Priority: Advanced Features & Polish</strong>", "md_TODO.html#autotoc_md258", null ]
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
"001__primitives_8c.html",
"203__complex_8c.html#aede9c690b1c97a1302526c2d95c65564",
"abi__arm64__common_8h.html#a1a804a261c22318a78552ce20a670ae3",
"abi__x64__emitters_8c.html#a877fb1f8f0703500d3c1210976a4f98e",
"group__introspection__api.html#ga3b75e8481ac13d11faa15046fc4adb66",
"md_SECURITY.html#autotoc_md252",
"structinfix__arg__location.html#a4f53bb713bc5749863d8ba2633b74604"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';