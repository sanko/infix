# FFI Signature Format Specification v1.0

### Part 1: Introduction

#### 1.1 The Challenge of Interoperability

The core challenge of any FFI is establishing a precise, unambiguous contract between the caller and the callee. Both sides must agree on the exact size, alignment, and representation of every piece of data.

#### 1.2 The Limitations of C Declarations

C's declaration syntax, while powerful, is notoriously difficult for both humans and machines to parse, often hiding the true memory layout of data. A declaration like `void (*(*f[])())()` is a testament to this complexity.

#### 1.3 Our Solution: A Human-First Signature System

This document specifies a string-based representation of C types and function signatures, built on three core principles:

1.  **Human-Readability First:** The syntax is intuitive and prioritizes clarity.
2.  **Unambiguous and Consistent:** The grammar is designed to be parsed linearly without ambiguity.
3.  **Developer-Centric Type System:** It provides two tiers of types: abstract C-style keywords for portability, and explicit fixed-width keywords for precise layout control.

#### 1.4 A Stateless, Composable Core

The core FFI library is **stateless** and does not maintain a global type registry. This empowers the user to manage named types in their own application space (e.g., in a hash map). The user is responsible for resolving these named types into a final, fully-qualified signature string before passing it to the stateless FFI core.

***

## Part 2: The Type System Reference

The signature system is composed of primitive types, type constructors, and composite data structures.

### 2.1 Tier 1: Abstract C Types

These keywords represent standard C types whose size can vary by platform.

| Signature   | Size                | C/C++ Equivalent     | Description                                                                 |
| :---------- | :------------------ | :------------------- | :-------------------------------------------------------------------------- |
| `void`      | N/A                 | `void`               | Represents the absence of a value.                                          |
| `char`      | 8 bits              | `signed char`        | A signed 8-bit integer.                                                     |
| `uchar`     | 8 bits              | `unsigned char`      | An unsigned 8-bit integer.                                                  |
| `short`     | 16 bits             | `short`              | A signed integer of at least 16 bits.                                       |
| `ushort`    | 16 bits             | `unsigned short`     | An unsigned integer of at least 16 bits.                                    |
| `int`       | 32 bits             | `int`                | The platform's native signed integer, usually 32 bits.                      |
| `uint`      | 32 bits             | `unsigned int`       | The platform's native unsigned integer.                                     |
| `long`      | **32 or 64 bits**   | `long`               | **The key abstract integer.** 32 bits on 64-bit Windows, 64 bits on Linux. |
| `ulong`     | **32 or 64 bits**   | `unsigned long`      | The unsigned version of `long`.                                             |
| `longlong`  | 64 bits             | `long long`          | A signed integer of at least 64 bits.                                       |
| `ulonglong` | 64 bits             |`unsigned long long`| An unsigned integer of at least 64 bits.                                    |
| `float`     | 32 bits             | `float`              | A 32-bit single-precision floating-point number.                          |
| `double`    | 64 bits             | `double`             | A 64-bit double-precision floating-point number.                          |
| `long double`| **Varies**         | `long double`        | 80-bit (x86), 128-bit (AArch64), or 64-bit (MSVC) float. Use with caution. |

### 2.2 Tier 2: Explicit Fixed-Width Types

These keywords are used when the exact size of a type is known and required.

| Signature Keyword | Common C Equivalent  | Size               | Description                                     |
| :---------------- | :------------------- | :----------------- | :---------------------------------------------- |
| `int8`, `uint8`   | `int8_t`, `uint8_t`    | 8 bits             | Explicitly-sized 8-bit signed/unsigned integers.  |
| `int16`, `uint16` | `int16_t`, `uint16_t`  | 16 bits            | Explicitly-sized 16-bit signed/unsigned integers. |
| `int32`, `uint32` | `int32_t`, `uint32_t`  | 32 bits            | Explicitly-sized 32-bit signed/unsigned integers. |
| `int64`, `uint64` | `int64_t`, `uint64_t`  | 64 bits            | Explicitly-sized 64-bit signed/unsigned integers. |
| `int128`, `uint128`| `__int128_t`        | 128 bits           | 128-bit integers, a common compiler extension.  |
| `float32`         | `float`              | 32 bits            | An explicit alias for a 32-bit float.             |
| `float64`         | `double`             | 64 bits            | An explicit alias for a 64-bit float.             |
| `float80`         | `long double` (x86)  | 80 bits            | An 80-bit extended-precision float.               |
| `float128`        | `long double` (PPC/AArch64) | 128 bits       | A 128-bit quadruple-precision float.              |

### 2.3 Advanced Numeric and Vector Types

| Name | Signature Syntax | C Equivalent | Description |
| :--- | :--- | :--- | :--- |
| **Complex Number** | `c[<type>]` | `float _Complex` | A complex number constructed from a floating-point `<type>`. Layout is `[2:<type>]`. |
| **SIMD Vector** | `v[<N>:<type>]` | `__m128d`, etc. | A SIMD vector with `N` elements of a primitive `<type>`. |

### 2.4 Type Constructors and Composite Structures

| Name                 | Syntax                                           | Description                                                                                                                                                              |
| :------------------- | :----------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Pointer**          | `*<type>`                               | The asterisk `*` is the universal prefix for a pointer to any other valid type. `*void` is the generic pointer.                                                              |
| **Array**            | `[<size>:<type>]`                         | A fixed-size array.                                                                                                                                                      |
| **Struct**           | `struct<Name>{...}` <br/> `{...}`            | A C `struct`, defined by its `{...}` body.                                                                                                                               |
| **Packed Struct**    | `!{...}` <br/> `!N:{...}`                    | A packed `struct`. `!{...}` defaults to 1-byte alignment. `!N:{...}` specifies an explicit N-byte alignment. |
| **Union**            | `union<Name><...>` <br/> `<...>`             | A C `union`, defined by its `<...>` body.                                                                                                                                |
| **Enum**             | `e<Name>:<type>` <br/> `e:<type>`           | A C `enum`. This is a semantic alias for an underlying integer `<type>`, which is **required**.                                                                        |
| **Function Signature** | `(<arg_types>) -> <return_type>`          | Defines the type of a function. Arguments may be named (`(name:type)`).                                                                                                  |
| **Variadic Signature** | `(<fixed_args>; <variadic_args>) -> <return_type>` | Defines a variadic function. A semicolon `;` separates the fixed arguments from the variadic ones.                                                                 |
| **Function Pointer** | `*((<arg_types>) -> <return_type>)`        | A pointer to a function.                                                                                                                                                 |

***

### Part 3: Examples, Best Practices, and Usage

#### 3.1 Syntax Showcase

| FFI Signature                                        | Breakdown                                                                                                             |
| :--------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------- |
| `int`                                                | A standard C signed integer.                                                                                        |
| `*char`                                              | A pointer to a C `signed char`.                                                                                       |
| `**void`                                             | A pointer to a generic `void` pointer.                                                                                |
| `[16:char]`                                          | An array of 16 signed characters.                                                                                     |
| `*[16:char]`                                         | A pointer to an array of 16 signed characters.                                                                        |
| `{int, float}`                                       | An anonymous struct containing an `int` followed by a `float`.                                                        |
| `{id:uint64, score:double}`                          | An anonymous struct with two named fields.                                                                            |
| `!{id:uint16, status:char}`                           | A packed struct (1-byte alignment). `status` will be at offset 2.                                                     |
| `!4:{a:char, b:longlong}`                             | A packed struct with 4-byte alignment. `b` will be padded to start at offset 4.                                       |
| `<int, float64>`                                     | An anonymous union that can hold either an `int` or a 64-bit `float64`.                                               |
| `() -> void`                                         | A function that takes no arguments and returns nothing.                                                               |
| `(*char, int) -> int`                                | A function that takes a `*char` and an `int`, and returns an `int`.                                                   |
| `(*char; int, double) -> int`                        | A variadic call like `printf`. The semicolon `;` marks the start of the variadic part.                                |
| `*((int, int) -> int)`                               | A pointer to a function that takes two `int`s and returns an `int`.                                                   |
| `struct<Ctx>{ data:*void, callback:*( (int) -> void ) }` | A struct with a function pointer field named `callback`.                                                              |
| `c[float]`                                           | A C `float _Complex` number.                                                                                          |
| `v[4:float]`                                         | A 128-bit SIMD vector containing four 32-bit floats.                                                                  |

#### 3.2 Architectural Pattern: Define and Use

This example demonstrates the "define once, use by reference" pattern that the stateless FFI architecture enables. The user's application or binding is responsible for resolving named types into a complete, self-contained signature string before passing it to the `infix` core.

***

## Part 4: Technical Specification and Design Rationale

#### 4.1 Whitespace and Comments
Insignificant whitespace (spaces, tabs, newlines) is permitted between any two tokens and should be ignored. Comments begin with a hash symbol (`#`) and continue to the end of the line.

#### 4.2 EBNF Grammar

This Extended Backus-Naur Form grammar formally defines the signature format.

```ebnf
signature           ::= function_type | value_type
value_type          ::= pointer_type | array_type | aggregate_type | enum_type | complex_type | vector_type | primitive_type | grouped_type

pointer_type        ::= '*' value_type
array_type          ::= '[' Integer ':' value_type ']'
grouped_type        ::= '(' value_type ')'

aggregate_type      ::= struct_type | union_type | packed_struct_type
struct_type         ::= ( 'struct' '<' Identifier '>' )? '{' member_list? '}'
packed_struct_type  ::= '!' ( Integer ':' )? '{' member_list? '}'
union_type          ::= ( 'union' '<' Identifier '>' )? '<' member_list? '>'
member_list         ::= member ( ',' member )*
member              ::= ( Identifier ':' )? value_type

enum_type           ::= 'e' ( '<' Identifier '>' )? ':' primitive_type
complex_type        ::= 'c' '[' value_type ']'
vector_type         ::= 'v' '[' Integer ':' value_type ']'

function_type       ::= '(' arg_list? ')' '->' value_type
arg_list            ::= fixed_args ( ';' variadic_args )?
fixed_args          ::= arg ( ',' arg )*
variadic_args       ::= arg ( ',' arg )*
arg                 ::= ( Identifier ':' )? value_type

primitive_type      ::= 'void' | 'bool' | 'char' | 'uchar' | 'short' | 'ushort' | 'int' | 'uint' | 'long' | 'ulong' | 'longlong' | 'ulonglong' | 'float' | 'double' | 'long_double' | 'int8' | 'uint8' | 'int16' | 'uint16' | 'int32' | 'uint32' | 'int64' | 'uint64' | 'int128' | 'uint128' | 'float32' | 'float64' | 'float80' | 'float128'

Identifier          ::= [a-zA-Z_] [a-zA-Z0-9_]*
Integer             ::= [0-9]+
```

#### 4.3 Design Rationale: Why This Syntax?

1.  **Readability over Brevity:** The two-tier type system (`int` vs. `int32`) directly maps to developer intent ("portability" vs. "specific layout").
2.  **Unambiguous Grammar:** Using a pure prefix for pointers (`*`) and clear delimiters for all other composites (`[]`, `{}`, `<>`) eliminates ambiguity and allows for simple, linear parsing.
3.  **Consistency:** The `c[...]` and `v[...]` syntax for complex and vector types creates a consistent "family" of specialized numeric constructors.

#### 4.4 Comparison with Other Systems

*   **vs. Itanium C++ ABI:** Itanium is a "write-only" format designed for linkers. Our system is designed for humans to read and write.
*   **vs. Python's `ctypes`:** `ctypes` uses a programmatic, object-oriented approach. Our format is a standalone, declarative string that can be used by *any* language.
*   **vs. `dyncall`'s Signature Format:**
    *   **Philosophy:** `dyncall`'s format is a flat string of single characters (e.g., `iSl)d`), prioritizing brevity. Our system prioritizes human readability (`(int, ushort, longlong) -> double`).
    *   **Expressiveness:** The `dyncall` signature can only describe primitive types. Our format treats complex data structures as first-class citizens. Our format answers, "What is the complete data contract for this function, including the shape of all its related data structures?"
