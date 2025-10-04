# The `infix` Signature Language Reference

The `infix` signature language is a powerful mini-language designed to describe C function and data types in a concise, readable string. It is the engine behind the high-level `infix_*_create` and `infix_*_from_signature` APIs.

## General Format

A **function signature** has the format `"arguments => return_type"`.

-   The `arguments` part is a comma-separated list of type specifiers.
-   The `=>` token separates arguments from the return type.
-   The `return_type` is a single type specifier.

A **single data type** is just the type specifier itself (e.g., `"{i,d}*"`).

## Primitives

These single-character specifiers map to common C types.

| Specifier | C Type                | Notes                                        |
| :-------- | :-------------------- | :------------------------------------------- |
| `v`       | `void`                | Only valid as a return type.                 |
| `b`       | `_Bool` / `bool`      |                                              |
| `c`       | `char`                | Assumed to be `uint8_t` for ABI purposes.    |
| `a`       | `int8_t`              |                                              |
| `h`       | `uint8_t`             |                                              |
| `s`       | `int16_t`             |                                              |
| `t`       | `uint16_t`            |                                              |
| `i`       | `int32_t`             |                                              |
| `j`       | `uint32_t`            |                                              |
| `l`       | `long`                | **Warning:** Size is platform-dependent.     |
| `m`       | `unsigned long`       | **Warning:** Size is platform-dependent.     |
| `x`       | `int64_t`             |                                              |
| `y`       | `uint64_t`            | Also used for `size_t` on 64-bit systems.    |
| `n`       | `__int128_t`          | Non-standard, GCC/Clang only.                |
| `o`       | `__uint128_t`         | Non-standard, GCC/Clang only.                |
| `f`       | `float`               |                                              |
| `d`       | `double`              |                                              |
| `e`       | `long double`         | **Warning:** Size and representation vary.   |

## Type Constructors and Modifiers

These characters are used to build complex types from primitives.

-   **Pointer (`*`)**: A postfix modifier that creates a pointer to the preceding type. It can be chained.
    -   `i*` -> `int*`
    -   `v**` -> `void**`

-   **Array (`[...]`)**: `[size]type`. Defines a fixed-size array of a given type.
    -   `[10]i` -> `int[10]`
    -   `[5]{i,d}` -> `struct { int; double; }[5]`

-   **Grouping (`(...)`)**: Overrides the default right-to-left precedence. This is essential for creating pointers to complex types like arrays.
    -   `[10]i*` -> `int* [10]` (An array of 10 pointers to int)
    -   `([10]i)*` -> `int (*)[10]` (A pointer to an array of 10 ints)

-   **Struct (`{...}`)**: A comma-separated list of member types enclosed in curly braces.
    -   `{i,d,c*}` -> `struct { int; double; const char*; }`

-   **Union (`<...>`):** A comma-separated list of member types enclosed in angle brackets.
    -   `<f,y>` -> `union { float; uint64_t; }`

-   **Packed Struct (`p(...)`)**: `p(size,align){type@offset,...}`. Defines a struct with an explicit, non-standard memory layout. `size` and `align` are integer byte values, and each member is followed by `@` and its byte offset.
    -   `p(5,1){c@0,i@1}` -> `_Pragma("pack(1)") struct { char c; int i; }`

-   **Function Pointer (`(...)`)**: A full function signature nested within parentheses acts as a function pointer type. For ABI purposes, this is treated as a `void*`.
    -   `(i,d=>v)` -> `void (*)(int, double)`
    -   `(i,d=>v)*` -> `void (**)(int, double)` (A pointer to a function pointer)

## Delimiters and Separators

-   **`,` (Comma)**: Separates arguments in a function signature or members in a struct/union.
-   **`;` (Semicolon)**: In a function signature, marks the end of fixed arguments and the beginning of variadic arguments.
-   **`:` (Colon)**: Separates a member name from its type in a struct or union (e.g., `{id:i}`). Naming is optional and used for introspection.
-   **`@` (At sign)**: Separates a member type from its byte offset within a packed struct.

## Examples

| C Function Signature | `infix` Signature String |
| :--- | :--- |
| `int max(int a, int b);` | `"i,i=>i"` |
| `void print_point(const Point* p);` <br> `struct Point { int x; double y; }` | `"{i,d}*=>v"` |
| `int printf(const char* format, ...);` | `"c*;=>i"` |
| `void register_callback(void (*cb)(int));` | `"(i=>v)*=>v"` |
| `User** find_users(int* count);` <br> `struct User { const char* name; int id; }` | `i*=>{name:c*,id:i}**` |
