## FFI Signature Format Specification v1.0

### Part 1: Introduction

#### 1.1 The Challenge of Interoperability

In modern software development, it is rare for a system to be built in a single programming language. High-performance libraries are often written in C, C++, or Rust, while applications are built in Python, C#, Java, or JavaScript. The bridge between these worlds is the Foreign Function Interface (FFI). An FFI allows code written in one language to call functions and manipulate data structures defined in another.

The core challenge of any FFI is establishing a precise, unambiguous contract between the caller and the callee. Both sides must agree on the exact size, alignment, and representation of every piece of data. Failure to do so results in stack corruption, crashes, and security vulnerabilities.

#### 1.2 The Limitations of C Declarations

For decades, the de facto standard for this contract has been the C header file. However, C's declaration syntax, while powerful, is notoriously difficult for both humans and machines to parse. It requires a complex "spiral rule" to decipher, is filled with ambiguity, and often hides the true memory layout of data. A declaration like `void (*(*f[])())()` is a testament to this complexity, being nearly unreadable while describing a valid type.

#### 1.3 Our Solution: A Human-First Signature System

This document specifies a new FFI signature format designed from the ground up to solve these problems. It is a concise, string-based representation of C types and function signatures, built on three core principles:

1.  **Human-Readability First:** The syntax is intuitive and immediately understandable to a developer familiar with C-family languages. It prioritizes clarity over absolute, machine-focused compactness.
2.  **Unambiguous and Consistent:** The grammar is designed to be parsed linearly (left-to-right) without the precedence battles and ambiguities of C's syntax. A given symbol or structure has a single, consistent meaning.
3.  **Developer-Centric Type System:** It provides two tiers of types: abstract C-style keywords for platform portability, and explicit fixed-width keywords for when precise memory layout is paramount.

#### 1.4 A Stateless, Composable Core

A key architectural principle of this specification is that the core FFI library remains **stateless**. The FFI's responsibility is to parse a complete, self-contained signature string and prepare a function call. It does not maintain a global type registry.

This design empowers the user. The management of named types is handled by the user or a higher-level binding generator, typically through a simple dictionary or map. This allows for maximum flexibility, composability, and thread-safety. A user can maintain separate type registries for different libraries and compose them as needed. The process is simple:

1.  Define complex types using their full, descriptive signature.
2.  Store these definitions in a user-space registry (e.g., a hash map).
3.  When preparing a function call, use a simple string replacement or a more sophisticated resolver to construct the final, fully-qualified signature string.
4.  Pass this complete string to the stateless FFI core.

This separation of concerns—type management vs. call invocation—is a cornerstone of this design's robustness.

***

## Part 2: The Type System Reference

The signature system is composed of primitive types, type constructors, composite data structures, and function types.

### 2.1 Tier 1: Abstract C Types

These keywords represent standard C types whose size can vary by platform. The FFI implementation is responsible for resolving them to the correct size and alignment for the target ABI. Use these for portable bindings to standard C libraries.

| Signature   | Size                | C/C++ Equivalent     | Rust Equivalent             | Python `ctypes` Equivalent | Description                                                                 |
| :---------- | :------------------ | :------------------- | :-------------------------- | :------------------------- | :-------------------------------------------------------------------------- |
| `void`      | N/A                 | `void`               | `()` (unit type)            | `None` (return value)      | Represents the absence of a value, typically for a function's return.         |
| `char`      | 8 bits              | `signed char`        | `i8` (`std::os::raw::c_char`) | `ctypes.c_char`            | A signed 8-bit integer, conventionally used for ASCII characters.         |
| `uchar`     | 8 bits              | `unsigned char`      | `u8` (`std::os::raw::c_uchar`)| `ctypes.c_ubyte`           | An unsigned 8-bit integer.                                                  |
| `short`     | 16 bits             | `short`              | `i16` (`std::os::raw::c_short`)| `ctypes.c_short`           | A signed integer of at least 16 bits.                                       |
| `ushort`    | 16 bits             | `unsigned short`     | `u16` (`std::os::raw::c_ushort`)| `ctypes.c_ushort`          | An unsigned integer of at least 16 bits.                                    |
| `int`       | 32 bits             | `int`                | `i32` (`std::os::raw::c_int`) | `ctypes.c_int`             | The platform's native signed integer; at least 16 bits, usually 32.         |
| `uint`      | 32 bits             | `unsigned int`       | `u32` (`std::os::raw::c_uint`)| `ctypes.c_uint`            | The platform's native unsigned integer.                                     |
| `long`      | **32 or 64 bits**   | `long`               | `i32`/`i64` (`c_long`)      | `ctypes.c_long`            | **The key abstract integer.** 32 bits on 64-bit Windows, 64 bits on Linux. |
| `ulong`     | **32 or 64 bits**   | `unsigned long`      | `u32`/`u64` (`c_ulong`)     | `ctypes.c_ulong`           | The unsigned version of `long`.                                             |
| `longlong`  | 64 bits             | `long long`          | `i64` (`c_longlong`)        | `ctypes.c_longlong`        | A signed integer of at least 64 bits.                                       |
| `ulonglong` | 64 bits             |`unsigned long long`| `u64` (`c_ulonglong`)       | `ctypes.c_ulonglong`       | An unsigned integer of at least 64 bits.                                    |
| `float`     | 32 bits             | `float`              | `f32`                       | `ctypes.c_float`           | A 32-bit single-precision floating-point number.                          |
| `double`    | 64 bits             | `double`             | `f64`                       | `ctypes.c_double`          | A 64-bit double-precision floating-point number.                          |

### 2.2 Tier 2: Explicit Fixed-Width Types

These keywords are used when the exact size of a type is known and required. This is essential for network protocols, file formats, and fixed-layout APIs.

| Signature Keyword | Common C Equivalent  | Size               | Description                                     |
| :---------------- | :------------------- | :----------------- | :---------------------------------------------- |
| `int8`, `uint8`   | `int8_t`, `uint8_t`    | 8 bits             | Explicitly-sized 8-bit signed/unsigned integers.  |
| `int16`, `uint16` | `int16_t`, `uint16_t`  | 16 bits            | Explicitly-sized 16-bit signed/unsigned integers. |
| `int32`, `uint32` | `int32_t`, `uint32_t`  | 32 bits            | Explicitly-sized 32-bit signed/unsigned integers. |
| `int64`, `uint64` | `int64_t`, `uint64_t`  | 64 bits            | Explicitly-sized 64-bit signed/unsigned integers. |
| `int128`, `uint128`| `__int128_t`        | 128 bits           | 128-bit integers, a common compiler extension.  |
| `float32`         | `float`              | 32 bits            | An explicit alias for a 32-bit float.             |
| `float64`         | `double`             | 64 bits            | An explicit alias for a 64-bit float.             |
| `float80`         | `long double` (x86)  | 80 bits            | An 80-bit extended-precision float, used by x86 ABIs. |
| `float128`        | `long double` (PPC/SPARC) | 128 bits           | A 128-bit quadruple-precision float.              |

### 2.3 Advanced Numeric and Vector Types

These are defined for forward compatibility in high-performance computing.

| Name | Signature Syntax | C Equivalent | Description |
| :--- | :--- | :--- | :--- |
| **Complex Number** | `c[<type>]` | `float _Complex` | A complex number, constructed from a floating-point `<type>`. The memory layout is equivalent to `[2:<type>]`. |
| **SIMD Vector** | `v[<N>:<type>]` | `__m128`, `__m256i` | A SIMD vector that should be passed in a dedicated vector register. |
| **Opaque Vector** | `v<bits>` | N/A | A fallback for rare cases where a SIMD value's element types are unknown. |

### 2.4 Type Constructors and Composite Structures

A key design principle is the distinction between types defined by a **body** (`struct`, `union`) and types that are semantic **aliases** (`enum`).

| Name                 | Syntax                                           | Description                                                                                                                                                                                                                                                                                            |
| :------------------- | :----------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Pointer**          | `*<type>`                               | The asterisk `*` is the universal prefix for a pointer to any other valid type. `*void` is the generic pointer.                                                                                                                                                               |
| **Array**            | `[<size>:<type>]`                         | A fixed-size array. The colon `:` separates the size descriptor from the element type.                                                                                                                                                                                    |
| **Struct**           | `struct<Name>{...}` <br/> `{...}`            | A C `struct`, defined by its `{...}` body. The named form is for definition; the anonymous form is for inline use.                                                                                                                                                             |
| **Union**            | `union<Name><...>` <br/> `<...>`             | A C `union`, defined by its `<...>` body. The named form is for definition; the anonymous form is for inline use.                                                                                                                                                              |
| **Enum**             | `e<Name>:<type>` <br/> `e:<type>`           | A C `enum`. This is a semantic alias for an underlying integer `<type>`, which is **required**. The named form is for definition; the anonymous form `e:` is for inline use.                                                                                                    |
| **Function Signature** | `(<arg_types>) -> <return_type>`          | Defines the type of a function. Arguments may be named (`(name:type)`) or anonymous (`(type)`).                                                                                                                                                                            |
| **Function Pointer** | `*((<arg_types>) -> <return_type>)`        | A pointer to a function. This follows the universal pointer rule: it is a pointer `*` to a function signature type.                                                                                                                                                              |
| **Variadic Arguments** | `...`                                     | The ellipsis `...` token, which must appear as the last element in a function's argument list.                                                                                                                                                                         |
| **Annotations**      | `"name" <type_or_signature>`              | Optional string literal prefixes that provide additional ABI details. Standardized annotations include `"stdcall"`, `"cdecl"`, and `"fastcall"`. Interpretation of other annotations is implementation-defined.                                                            |

***

### Part 3: Examples, Best Practices, and Usage

#### 3.1 Syntax Showcase

This table provides a wide variety of examples to demonstrate the expressiveness and clarity of the signature format.

| FFI Signature                                        | Breakdown                                                                                                             |
| :--------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------- |
| `int`                                                | A standard C signed integer, typically 32 bits.                                                                       |
| `*char`                                              | A pointer to a standard C signed character.                                                                           |
| `**void`                                             | A pointer to a generic `void` pointer. Often used for out-parameters.                                                 |
| `[16:char]`                                          | An array of 16 signed characters.                                                                                     |
| `*[16:char]`                                         | A pointer to an array of 16 signed characters.                                                                        |
| `{int, float}`                                       | An anonymous struct containing an `int` followed by a `float`, with platform-default alignment.                       |
| `{id:uint64, score:double}`                          | An anonymous struct with two named fields, a `uint64` and a `double`.                                                 |
| `!{id:uint16, status:char}`                           | A packed struct (1-byte alignment) with two named fields. `status` will be at offset 2.                               |
| `!4:{a:char, b:longlong}`                             | A packed struct with 4-byte alignment. `b` will be padded to start at an offset of 4.                                 |
| `{a:int, nested:{b:char, c:char}}`                    | A struct containing a nested anonymous struct.                                                                        |
| `<int, float64>`                                     | An anonymous union that can hold either an `int` or a 64-bit `float64`.                                               |
| `<as_int:int32, as_ptr:*void>`                        | An anonymous union with two named fields, a 32-bit `int` and a generic pointer.                                       |
| `() -> void`                                         | A function that takes no arguments and returns nothing.                                                               |
| `(*char, int) -> int`                                | A function that takes a `char*` and an `int`, and returns an `int`.                                                   |
| `(*char, ... ) -> int`                                | `printf`: A variadic function that must take a `char*` and can take any number of subsequent arguments.               |
| `"stdcall" (*void, uint32) -> int`                     | A Windows API-style function using the `stdcall` calling convention.                                                  |
| `e:int`                                              | An anonymous enum whose underlying ABI type is `int`.                                                                 |
| `e<Color>:uint8`                                     | The definition of a named enum `Color` whose underlying ABI type is `uint8`.                                          |
| `struct<Point>{x:float, y:float}`                     | The definition of a named struct `Point` with two float fields.                                                       |
| `*struct<Point>`                                     | A pointer to a previously-defined `struct<Point>`. This is the "reference" form.                                      |
| `union<Value><as_int:int, as_ptr:*void>`              | The definition of a named union `Value`.                                                                              |
| `*union<Value>`                                      | A pointer to a previously-defined `union<Value>`.                                                                     |
| `*((int, int) -> int)`                               | A pointer to a function that takes two `int`s and returns an `int`.                                                   |
| `struct<Ctx>{ data:*void, callback:*( (int) -> void ) }` | A struct with a function pointer field named `callback`. The callback takes an `int` and returns `void`.              |
| `c[float]`                                           | A C `float _Complex` number, with the same memory layout as `[2:float]`.                                              |
| `v[4:float32]`                                       | A 128-bit SIMD vector containing four 32-bit floats (e.g., SSE `__m128`).                                             |

#### 3.2 Architectural Pattern: Define and Use

This example demonstrates the "define once, use by reference" pattern that the stateless FFI architecture enables.

*   **C Code:**
    ```c
    enum Status { OK, PENDING, ERROR };
    struct Result {
      long long id;
      enum Status status;
    };
    int process_results(struct Result results[], int count);
    ```

*   **Step 1: Conceptually Define Types in a User-Space Registry**
    ```javascript
    // A simple key-value map in the user's application
    const type_registry = {
      "Status": "e<Status>:int",
      "Result": "struct<Result>{id:longlong, status:e<Status>}"
    };
    ```

*   **Step 2: Define the Function Signature Using References**
    *   **High-Level Signature:** `(*struct<Result>, int) -> int`

*   **Step 3: Resolve the Final Signature String**
    *   The user's wrapper code resolves the references, producing a complete, self-contained string to pass to the FFI.
    *   **Final Resolved Signature:** `(*struct<Result>{id:longlong, status:e<Status>:int}, int) -> int`

*   **Step 4: Pass to the Stateless FFI Core**
    *   The FFI core receives this final string, parses it, and prepares the call without needing any external context.

#### 3.3 Common Pitfalls and Solutions

1.  **Pitfall: `long double` Ambiguity**
    *   **Problem:** A library is compiled with GCC on Linux, where `long double` is an 80-bit float. The user writes the signature as `double`, assuming it's 64 bits. This causes a stack corruption.
    *   **Solution:** The signature must describe the **target library's ABI**, not the host's. The user must be explicit and use the correct Tier 2 type. For a GCC Linux library, the correct signature is `float80`. For an MSVC Windows library, the correct signature is `float64` (or `double`).

2.  **Pitfall: Pointer Ownership and Memory Leaks**
    *   **Problem:** A C function `char* create_message()` returns a newly allocated string, but this is not captured in the signature, leading to memory leaks.
    *   **Solution:** While a full ownership system is beyond the scope of this v1.0 specification, the `"owned"` and `"borrowed"` annotations are reserved for this purpose. An FFI implementation can use them to provide safer memory management. For example, a binding generator seeing `() -> "owned" *char` could automatically generate code to free the string's memory when it is no longer in use.

#### 3.4 Benefits for Tooling and Mental Modeling

*   **Introspection:** This format is a machine-readable schema. A tool can parse `!{id:uint16, data:[16:uint8]}` and instantly calculate its size, determine field offsets, generate GUIs, or create safe, high-level object bindings in the host language.
*   **Mental Model:** The linear, left-to-right syntax allows a developer to reason about complex C types without cognitive overhead. The signature `*([16:*{...}])` is read simply as "a pointer to an array of 16 pointers to a struct." This replaces the error-prone "[spiral rule](https://c-faq.com/decl/spiral.anderson.html)" of C with a simple, declarative description of the type.

***

## Part 4: Technical Specification and Design Rationale

#### 4.1 Whitespace and Comments
Insignificant whitespace (spaces, tabs, newlines) is permitted between any two tokens and should be ignored by a compliant parser. Comments begin with a hash symbol (`#`) and continue to the end of the line.

#### 4.2 EBNF Grammar

This Extended Backus-Naur Form grammar formally defines the signature format.

```ebnf
signature           ::= annotation* ( function_type | value_type )

annotation          ::= StringLiteral

value_type          ::= pointer_type | array_type | struct_type | union_type | complex_type | simd_type | enum_type | primitive_type

pointer_type        ::= '*' ( value_type | function_type )
array_type          ::= '[' Integer ':' value_type ']'

struct_type         ::= packed_prefix? ( 'struct' '<' Identifier '>' )? '{' field_list? '}'
packed_prefix       ::= ( '!' Integer ':' ) | '!'
union_type          ::= ( 'union' '<' Identifier '>' )? '<' field_list? '>'
field_list          ::= field ( ',' field )*
field               ::= ( Identifier ':' )? value_type

enum_type           ::= 'e' ( '<' Identifier '>' )? ':' value_type

complex_type        ::= 'c' '[' float_type ']'
simd_type           ::= 'v' ( ( '[' Integer ':' value_type ']' ) | Integer )

function_type       ::= '(' arg_list? ')' '->' value_type
arg_list            ::= arg ( ',' arg )* ( ',' '...' )?
arg                 ::= ( Identifier ':' )? value_type

primitive_type      ::= abstract_type | fixed_width_type
float_type          ::= 'float' | 'double' | 'float32' | 'float64' | 'float80' | 'float128'

abstract_type       ::= 'void' | 'char' | 'uchar' | 'short' | 'ushort' | 'int' | 'uint' | 'long' | 'ulong' | 'longlong' | 'ulonglong' | float_type
fixed_width_type    ::= ('int' | 'uint') ('8' | '16' | '32' | '64' | '128') | 'float' ('32' | '64')

Identifier          ::= [a-zA-Z] [a-zA-Z0-9_]*
Integer             ::= [0-9]+
StringLiteral       ::= '"' [^"]* '"'
```

#### 4.3 Design Rationale: Why This Syntax?

1.  **The Two-Tier Type System over a Single-Character Encoding:** Our two-tier system (`int` vs. `int32`) directly maps to the developer's intent: "Do I want this to be portable or do I need a specific layout?" This is more explicit and readable than a machine-first encoding like the Itanium ABI's (`i` vs. `x`).

2.  **Universal Prefix Modifiers and Delimited Constructors:** C's syntax complexity stems from the precedence battle between prefix `*` and postfix `[]` and `()`. Our system uses a pure prefix approach for pointers (`*`) and clear delimiter-based approaches for all other composites, eliminating ambiguity and allowing for simple, linear parsing.

3.  **Body vs. Alias Principle:** The syntax distinguishes between types defined by a body and types that are semantic aliases. Types with a member list (`struct`, `union`) use a full keyword when named. Types that are aliases for an underlying type (`enum`) use a concise symbolic constructor (`e`).

#### 4.4 Comparison with Other Systems

*   **vs. Itanium C++ ABI:** Itanium is a "write-only" format designed for linkers. It is maximally compact but unreadable. Our system is designed for humans to read and write, making a deliberate trade-off in verbosity for a massive gain in clarity.
*   **vs. Python's `ctypes`:** `ctypes` uses a programmatic, object-oriented approach. Our format is a standalone, declarative string that can be used by *any* language to generate bindings. It is a universal schema, not a language-specific implementation.
*   **vs. `dyncall`'s Signature Format:** The `dyncall` library's signature format is a prime example of a minimalist, machine-centric design. `dyncall` is what inspired me to write `infix`.
    *   **Philosophy:** `dyncall`'s format is a flat string of single characters (e.g., `iSl)d`). This prioritizes brevity and parsing efficiency. Our system prioritizes human readability (`(int, ushort, longlong) -> double`).
    *   **Expressiveness:** The `dyncall` signature can only describe primitive types. It cannot describe the layout of a struct, the size of an array, or the signature of a function pointer.
    *   **Our Advantage:** Our system treats complex data structures as first-class citizens. The signature `!{id:uint16, data:[16:uint8]}` is a complete schema. `dyncall` answers, "Which registers do I put these primitives into?" Our format answers, "What is the complete data contract for this function, including the shape of all its related data structures?"

#### 4.5 Rationale for Advanced Data Types

1.  **SIMD Vectors:** The `v[<N>:<type>]` syntax was adopted because it is highly descriptive. The leading `v` acts as a crucial flag to the FFI implementation, indicating that this is a value destined for a SIMD register. The array-like portion provides the rich metadata needed for both ABI correctness and high-level binding generation.

2.  **Complex Numbers:** The `c[<type>]` syntax was adopted because it creates a direct, logical parallel with the `v[...]` syntax for SIMD vectors, establishing a consistent "family" of specialized numeric constructors. The mnemonic `c` for "complex" is exceptionally strong, making the syntax highly readable despite its conciseness.
