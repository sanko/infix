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
      [ "Our Pledge", "md_CODE__OF__CONDUCT.html#autotoc_md9", null ],
      [ "Our Standards", "md_CODE__OF__CONDUCT.html#autotoc_md10", null ],
      [ "Our Responsibilities", "md_CODE__OF__CONDUCT.html#autotoc_md11", null ],
      [ "Scope", "md_CODE__OF__CONDUCT.html#autotoc_md12", null ],
      [ "Enforcement", "md_CODE__OF__CONDUCT.html#autotoc_md13", null ],
      [ "Attribution", "md_CODE__OF__CONDUCT.html#autotoc_md14", null ]
    ] ],
    [ "Contributing to the infix FFI Library", "md_CONTRIBUTING.html", [
      [ "Code of Conduct", "md_CONTRIBUTING.html#autotoc_md4", null ],
      [ "How to Contribute", "md_CONTRIBUTING.html#autotoc_md5", null ]
    ] ],
    [ "Building and Integrating <tt>infix</tt>", "md_INSTALL.html", [
      [ "Prerequisites", "md_INSTALL.html#autotoc_md16", null ],
      [ "1. Building <tt>infix</tt> from Source", "md_INSTALL.html#autotoc_md18", [
        [ "Using xmake (Recommended)", "md_INSTALL.html#autotoc_md19", null ],
        [ "Using Perl", "md_INSTALL.html#autotoc_md20", null ],
        [ "Using CMake", "md_INSTALL.html#autotoc_md21", [
          [ "Using Makefiles", "md_INSTALL.html#autotoc_md26", [
            [ "GNU Make (Linux, macOS, BSDs)", "md_INSTALL.html#autotoc_md27", null ],
            [ "NMake (Windows with MSVC)", "md_INSTALL.html#autotoc_md30", null ]
          ] ],
          [ "Manual Compilation (Advanced)", "md_INSTALL.html#autotoc_md31", null ]
        ] ],
        [ "2. Integrating <tt>infix</tt> into Your Project", "md_INSTALL.html#autotoc_md33", [
          [ "Using CMake with <tt>find_package</tt>", "md_INSTALL.html#autotoc_md34", null ],
          [ "Using pkg-config", "md_INSTALL.html#autotoc_md35", null ],
          [ "Using xmake", "md_INSTALL.html#autotoc_md36", null ],
          [ "Using in Visual Studio Code", "md_INSTALL.html#autotoc_md37", [
            [ "Manual Integration into an Existing Project", "md_INSTALL.html#autotoc_md38", null ]
          ] ]
        ] ],
        [ "3. Packaging <tt>infix</tt> (For Maintainers)", "md_INSTALL.html#autotoc_md40", [
          [ "Linux Distributions (DEB/RPM)", "md_INSTALL.html#autotoc_md41", null ],
          [ "xmake Repository", "md_INSTALL.html#autotoc_md42", null ]
        ] ]
      ] ]
    ] ],
    [ "<tt>infix</tt>: A JIT-Powered FFI Library for C", "md_README.html", [
      [ "Key Features", "md_README.html#autotoc_md54", null ],
      [ "Who is this for?", "md_README.html#autotoc_md55", null ],
      [ "Quick Start: The Two APIs", "md_README.html#autotoc_md56", [
        [ "1. The Signature API (Recommended)", "md_README.html#autotoc_md57", [
          [ "Signature API Cheat Sheet", "md_README.html#autotoc_md58", null ]
        ] ],
        [ "2. The Manual API (Advanced)", "md_README.html#autotoc_md59", [
          [ "Manual API Cheat Sheet", "md_README.html#autotoc_md60", null ]
        ] ]
      ] ],
      [ "Powerful Introspection for Dynamic Data Marshalling", "md_README.html#autotoc_md61", null ],
      [ "Supported Platforms", "md_README.html#autotoc_md62", null ],
      [ "Building and Integrating", "md_README.html#autotoc_md63", null ],
      [ "Learn More", "md_README.html#autotoc_md64", null ],
      [ "License & Legal", "md_README.html#autotoc_md65", [
        [ "Code License", "md_README.html#autotoc_md66", null ],
        [ "Documentation License", "md_README.html#autotoc_md67", null ]
      ] ]
    ] ],
    [ "Security Policy", "md_SECURITY.html", [
      [ "Supported Versions", "md_SECURITY.html#autotoc_md43", null ],
      [ "Reporting a Vulnerability", "md_SECURITY.html#autotoc_md44", null ],
      [ "Security Model", "md_SECURITY.html#autotoc_md45", [
        [ "Mitigations", "md_SECURITY.html#autotoc_md46", [
          [ "1. W^X (Write XOR Execute) Memory Policy", "md_SECURITY.html#autotoc_md47", null ],
          [ "2. Use-After-Free Prevention (Guard Pages)", "md_SECURITY.html#autotoc_md48", null ],
          [ "3. Read-Only Context Hardening", "md_SECURITY.html#autotoc_md50", null ],
          [ "4. API Hardening Against Integer Overflows", "md_SECURITY.html#autotoc_md51", null ],
          [ "5. Continuous Security Validation (Fuzzing)", "md_SECURITY.html#autotoc_md52", null ]
        ] ]
      ] ]
    ] ],
    [ "<strong>Project Roadmap: infix FFI</strong>", "md_TODO.html", [
      [ "<strong>High Priority: Foundation & Stability</strong>", "md_TODO.html#autotoc_md68", null ],
      [ "<strong>Medium Priority: Expansion & Optimization</strong>", "md_TODO.html#autotoc_md69", null ],
      [ "<strong>Low Priority: Advanced Features & Polish</strong>", "md_TODO.html#autotoc_md70", null ]
    ] ]
  ] ]
];

var NAVTREEINDEX =
[
"index.html"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';