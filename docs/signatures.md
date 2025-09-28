# The `infix` Signature Language Reference

## Introduction

The `infix` signature language is a powerful, human-readable mini-language designed to describe C function and data types in a clear and unambiguous way. It is the engine behind the high-level `infix` APIs for creating FFI trampolines.

This language prioritizes **clarity, explicitness, and C-like familiarity** over extreme brevity. Its grammar is designed to be easy for developers to write correctly and for the parser to interpret without ambiguity.

## General Format

A **function signature** has the format: `"arguments -> return_type"`. A **single data type** is represented by its type specifier string.

### EBNF Grammar

For a formal definition, the language can be described by the following Extended Backus-Naur Form (EBNF) grammar:

```ebnf
signature      ::= arg_list, "->", type ;
arg_list       ::= [ type, { ",", type } ], [ ",", "..." ] | [ "..." ] | (* empty *) ;
type           ::= base_type, { postfix_modifier } ;
base_type      ::= primitive | aggregate | func_ptr ;
postfix_modifier ::= "*" | "[", number, "]" ;

primitive      ::= "void" | "bool" | "char" | "int8" | ... | "long_double" ;

aggregate      ::= [ "packed", "(", number, ",", number, ")" ], ( "struct" | "union" ), "{", member_list, "}" ;
member_list    ::= member, { member } ;
member         ::= type, [ identifier ], ";" ;
packed_member  ::= type, [ identifier ], "@offset", "(", number, ")", ";" ;

func_ptr       ::= "func", "(", arg_list, ")", "->", type ;

identifier     ::= letter, { letter | digit } ;
number         ::= digit, { digit } ;
```

### Core Rules

-   **Whitespace**: Arbitrary whitespace is permitted and ignored.
-   **Case Sensitivity**: All keywords and primitives must be lowercase.
-   **Delimiters**: Struct/union members must be separated by semicolons (`;`). Function arguments are separated by commas (`,`).
-   **Empty Constructs**: Empty member lists (`{}`), empty groupings (`()`), and empty packed structs are **invalid**.

## Type Definitions

### Primitives

Keywords are used for all primitive types for maximum clarity. The table below provides mappings to common language types.

| `infix` Keyword | C/C++ Type            | Rust Type | FORTRAN 90+ Type           | Notes                                |
|:----------------|:----------------------|:----------|:---------------------------|:-------------------------------------|
| `void`          | `void`                | `()`      | -                          | Only for return types or pointer targets. |
| `bool`          | `_Bool` / `bool`      | `bool`    | `LOGICAL(KIND=1)`          | Represents a single byte boolean.    |
| `char`          | `char`                | `u8`/`i8` | `CHARACTER(LEN=1)`         | Assumed unsigned for ABI purposes.   |
| `int8`          | `int8_t`              | `i8`      | `INTEGER(KIND=1)`          |                                      |
| `uint8`         | `uint8_t`             | `u8`      | `INTEGER(KIND=1)`          | Unsigned.                            |
| `int16`         | `int16_t`             | `i16`     | `INTEGER(KIND=2)`          |                                      |
| `uint16`        | `uint16_t`            | `u16`     | `INTEGER(KIND=2)`          | Unsigned.                            |
| `int32`         | `int32_t`             | `i32`     | `INTEGER(KIND=4)` / `INTEGER` | |
| `uint32`        | `uint32_t`            | `u32`     | `INTEGER(KIND=4)`          | Unsigned.                            |
| `int64`         | `int64_t`             | `i64`     | `INTEGER(KIND=8)`          |                                      |
| `uint64`        | `uint64_t`            | `u64`     | `INTEGER(KIND=8)`          | Also used for `size_t`. Unsigned.  |
| `int128`        | `__int128_t`          | `i128`    | -                          | Non-standard, GCC/Clang only.      |
| `uint128`       | `__uint128_t`         | `u128`    | -                          | Non-standard, GCC/Clang only.      |
| `float`         | `float`               | `f32`     | `REAL(KIND=4)` / `REAL`      |                                      |
| `double`        | `double`              | `f64`     | `REAL(KIND=8)` / `DOUBLE PRECISION` | |
| `long_double`   | `long double`         | -         | `REAL(KIND=16)`            | **Warning:** Size is platform-dependent. |
| `long`        | `long`           | |**Warning:** Size is platform-dependent.   |
| `ulong`       | `unsigned long`  |  |**Warning:** Size is platform-dependent.   |

### Aggregates

Aggregate types group other types together. Member names are **optional**. This allows for concise, ABI-only definitions (`int32;`) or richer, introspectable types (`int32 id;`).

#### `struct` and `union`

A semicolon-separated list of C-style member declarations.

```c
// Struct with both named and unnamed members
struct {
    int32 id;             // Named member: type name;
    double;               // Unnamed member: type;
    char* name;
}
```

#### Nested Aggregates

Structs and unions can be nested to any depth, just like in C.

```c
struct {
    uint64_t packet_id;
    union {
        struct { uint32_t addr; uint16_t port; } tcp_info;
        uint8_t udp_mac;
    } transport_info;
}
```

#### Packed `struct`

An attribute preceding a `struct` declaration. Each member **must** have an explicit byte offset.

`packed(size, align) struct { member_declarations }`

```c
// Represents a C struct defined with #pragma pack(1)
packed(5, 1) struct {
    char tag @offset(0);
    int32 id @offset(1);
}
```

### Pointers and Arrays

-   **Pointer (`*`)**: A postfix modifier. The parser creates a rich pointer type, storing what it points to.
-   **Array (`[]`)**: A postfix modifier that can be applied to any type. For example:
    - `int32[10]`: An array of 10 integers.
    - `int32*[5][10]`: A 10-element array of 5-element arrays of pointers to integers.

### Function Pointers

Defined with an explicit `func` keyword.
`func(int32, double -> void)`

## Advanced Topics

### `void` and Zero-Argument Functions

The `void` keyword is **only valid as a return type** or pointer target (`void*`). To declare a function with **no arguments**, leave the argument list empty: `-> int32`.

### Precedence (Grouping)

The language's postfix `*` and `[]` system has a right-to-left evaluation order that mirrors C's, **eliminating the need for most grouping parentheses.**

#### Pointer to an Array
*   **C Syntax:** `struct Point (*p)[10];`
*   **Infix Syntax:** `struct { int32 x; int32 y; }[10]*`

The parser correctly interprets this as: ( (a struct) which is an array of 10 ) which is a pointer.

#### Array of Pointers
*   **C Syntax:** `struct Point* p[10];`
*   **Infix Syntax:** `struct { int32 x; int32 y; }*[10]`

The parser correctly interprets this as: ( (a struct) which is a pointer ) which is an array of 10.

### Variadic Functions (`...`)

Variadic functions are fully supported through a dedicated, high-level API.

The ellipsis token (`...`) is used in a signature to mark the function as variadic. This signature describes the *fixed* part of the function's arguments.

`"char*, ... -> int32"  // The signature for printf`

To generate a trampoline for a specific call, you combine this base signature with another string representing only the types of the variadic arguments for that call.

#### Forward Trampolines (Making a Variadic Call)
Use `infix_forward_create_variadic`, which combines a base signature with a second signature string for the variable part.

```c
// Goal: A trampoline for printf("Hello %s, num %d", "world", 42);

const char* base_sig = "char*, ... -> int32";
const char* variadic_sig = "char*, int32"; // The types for this specific call

infix_forward_t* trampoline;
infix_forward_create_variadic(&trampoline, base_sig, variadic_sig);

// Note: The C caller must still respect C's default argument promotions.
// A float argument must be passed as a double.
// `infix` generates the correct ABI code based on the provided types.
```

#### Reverse Trampolines (Creating a Variadic Callback)
To create a C-callable function pointer to a variadic handler, you provide the full signature of the function pointer type.

```c
// C Type: void (*log_handler)(int level, const char* fmt, ...);
const char* signature = "int32, char*, ... -> void";

infix_reverse_t* context;
// The user_callback_fn is the non-variadic C function that `infix` will call.
// Infix will marshal the fixed arguments and provide the variadic ones
// in a standard va_list.
infix_reverse_create(&context, signature, my_log_handler, my_data);
```
The exact mechanism for receiving the `va_list` in the final handler depends on the language binding using `infix`.

## Unsupported C Features (Pitfalls to Avoid)

-   **`typedef`**: Not supported. All types must be fully unrolled.
-   **`const`/`volatile`**: Ignored. Omit them from signatures.
-   **Bitfields & Flexible Array Members**: Not supported directly. Use `packed struct` with manual offsets to describe the surrounding layout.
-   **Recursive Structs**: The parser cannot handle directly recursive definitions like `struct Node { int32 data; Node* next; };`. **Workaround**: A pointer to an incomplete (or "opaque") type is valid. A linked list node would be defined as a struct containing a generic `void*` for its `next` field:
    ```c
    struct { int32 data; void* next; }
    ```
