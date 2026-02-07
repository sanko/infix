# The infix Signature and Type System

### Part 1: Introduction

#### 1.1 The Challenge of Interoperability

The core challenge of any Foreign Function Interface (FFI) is establishing a precise, unambiguous contract between the caller and the callee. Both sides must agree on the exact size, alignment, and representation of every piece of data to avoid memory corruption and undefined behavior.

#### 1.2 The Limitations of C Declarations

C's declaration syntax, while powerful, is notoriously difficult for both humans and machines to parse. It often hides the true memory layout of data, and complex declarations can be nearly indecipherable. A declaration like `void (*(*f[])())()` is a testament to this complexity.

#### 1.3 Our Solution: A Human-First Signature System

`infix` solves this with a string-based representation of C types and function signatures, built on three core principles:

1.  **Human-Readability First:** The syntax is intuitive, avoids cryptic abbreviations, and prioritizes clarity.
2.  **Unambiguous and Consistent:** The grammar is designed to be parsed linearly without ambiguity, using clear delimiters (`{}`, `[]`, `<>`) for composite types.
3.  **Developer-Centric Type System:** The language provides two tiers of primitive types: abstract C-style keywords (like `int`, `long`) for general use, and explicit fixed-width keywords (like `int32`, `uint64`) for precise layout control and maximum portability.

***

## Part 2: The Signature Language Reference

The signature language allows you to describe any C type as a string. All whitespace and C++-style line comments (`# ...`) are ignored, allowing you to format complex signatures for readability.

### 2.1 Primitives

#### Tier 1: Abstract C Types

These keywords represent standard C types whose size can vary by platform. They are useful for quick prototyping or interacting with older C APIs.

| `infix` Keyword | C/C++ Equivalent     | Common Size         | Description                                                                 |
| :-------------- | :------------------- | :------------------ | :-------------------------------------------------------------------------- |
| `void`          | `void`               | N/A                 | Represents the absence of a value. Valid only as a function return type.    |
| `bool`          | `bool`, `_Bool`      | 1 bit               | Binary true or false.                                                       |
| `char`          | `signed char`        | 8 bits              | A signed 8-bit integer.                                                     |
| `uchar`         | `unsigned char`      | 8 bits              | An unsigned 8-bit integer.                                                  |
| `short`         | `short`              | 16 bits             | A signed integer of at least 16 bits.                                       |
| `ushort`        | `unsigned short`     | 16 bits             | An unsigned integer of at least 16 bits.                                    |
| `int`           | `int`                | 32 bits             | The platform's native signed integer, usually 32 bits.                      |
| `uint`          | `unsigned int`       | 32 bits             | The platform's native unsigned integer.                                     |
| `long`          | `long`               | 32 or 64 bits       | **Platform-dependent.** 32 bits on 64-bit Windows, 64 bits on Linux/macOS.  |
| `ulong`         | `unsigned long`      | 32 or 64 bits       | The unsigned version of `long`.                                             |
| `longlong`      | `long long`          | 64 bits             | A signed integer of at least 64 bits.                                       |
| `ulonglong`     | `unsigned long long` | 64 bits             | An unsigned integer of at least 64 bits.                                    |
| `float`         | `float`              | 32 bits             | A 32-bit single-precision floating-point number.                            |
| `half`          | `_Float16`, `__fp16` | 16 bits             | A 16-bit half-precision floating-point number.                              |
| `double`        | `double`             | 64 bits             | A 64-bit double-precision floating-point number.                            |
| `longdouble`    | `long double`        | Varies              | 80-bit (x86), 128-bit (AArch64), or 64-bit (MSVC) float. Use with caution.  |
| `size_t`        | `size_t`             | 32 or 64 bits       | **Platform-dependent.** 32 bits on 64-bit Windows, 64 bits on Linux/macOS.  |
| `ssize_t`       | `ssize_t`            | 32 or 64 bits       | **Platform-dependent.** 32 bits on 64-bit Windows, 64 bits on Linux/macOS.  |

#### Tier 2: Explicit Fixed-Width Types (Recommended)

For maximum portability and control, these keywords guarantee the size of the type across all platforms.

| `infix` Keyword       | C/C++ Equivalent      | Size     | Description                                       |
| :-------------------- | :-------------------- | :------- | :------------------------------------------------ |
| `sint8`, `uint8`      | `int8_t`, `uint8_t`   | 8 bits   | Explicitly-sized 8-bit signed/unsigned integers.  |
| `sint16`, `uint16`    | `int16_t`, `uint16_t` | 16 bits  | Explicitly-sized 16-bit signed/unsigned integers. |
| `sint32`, `uint32`    | `int32_t`, `uint32_t` | 32 bits  | Explicitly-sized 32-bit signed/unsigned integers. |
| `sint64`, `uint64`    | `int64_t`, `uint64_t` | 64 bits  | Explicitly-sized 64-bit signed/unsigned integers. |
| `sint128`, `uint128`  | `__int128_t`          | 128 bits | 128-bit integers (GCC/Clang extension).           |
| `float16`             | `_Float16`            | 16 bits  | An explicit alias for a 16-bit half-precision float. |
| `float32`             | `float`               | 32 bits  | An explicit alias for a 32-bit float.             |
| `float64`             | `double`              | 64 bits  | An explicit alias for a 64-bit float.             |
| `char8_t`             | `char8_t`             | 8 bits   | An explicit alias for an 8-bit unsigned integer (UTF-8 character unit).  |
| `char16_t`            | `char16_t`            | 16 bits  | An explicit alias for a 16-bit unsigned integer (UTF-16 character unit). |
| `char32_t`            | `char32_t`            | 32 bits  | An explicit alias for a 32-bit unsigned integer (UTF-32 character unit). |

#### Tier 3: SIMD Vector Aliases

For convenience when working with common SIMD types on x86-64, `infix` provides the following keywords as aliases for the more verbose `v[...]` syntax.

| `infix` Keyword | C Equivalent | `infix` Equivalent | Description                                           |
| :-------------- | :----------- | :----------------- | :---------------------------------------------------- |
| `m256d`         | `__m256d`    | `v[4:double]`      | An AVX vector of four 64-bit `double`s.               |
| `m256`          | `__m256`     | `v[8:float]`       | An AVX vector of eight 32-bit `float`s.               |
| `m512d`         | `__m512d`    | `v[8:double]`      | An AVX-512 vector of eight 64-bit `double`s.          |
| `m512`          | `__m512`     | `v[16:float]`      | An AVX-512 vector of sixteen 32-bit `float`s.         |
| `m512i`         | `__m512i`    | `v[8:sint64]`      | An AVX-512 vector of eight 64-bit `long long` integers. |

### 2.2 Type Constructors and Composite Structures

These syntax elements allow you to build complex types from simpler ones.

| Name                 | `infix` Syntax                | Example Signature              | C/C++ Equivalent                                         |
| :------------------- | :---------------------------- | :----------------------------- | :------------------------------------------------------- |
| **Pointer**          | `*<type>`                     | `"*int"`, `"*void"`            | `int*`, `void*`                                          |
| **Struct**           | `{<members>}`                 | `"{int, double, *char}"`       | `struct { ... }`                                         |
| **Union**            | `<`<members>`>`               | `"<int, float>"`               | `union { ... }`                                          |
| **Array**            | `[<size>:<type>]`             | `"[10:double]"`                | `double[10]`                                             |
| **Function Pointer** | `(<args>)-><ret>`             | `"(int, int)->int"`            | `int (*)(int, int)`                                      |
| **_Complex**         | `c[<base_type>]`              | `"c[double]"`                  | `_Complex double`                                        |
| **SIMD Vector**      | `v[<size>:<type>]`            | `"v[4:float]"`                 | `__m128`, `__m512`, `float32x4_t`, `svfloat32_t`          |
| **Enum**             | `e:<int_type>`                | `"e:int"`                      | `enum { ... }`                                           |
| **Packed Struct**    | `!{...}` or `!<N>:{...}`      | `"!{char, longlong}"`          | `__attribute__((packed))`                                |
| **Variadic Function**| `(<fixed>;<variadic>)`        | `"(*char; int)->int"`          | `printf(const char*, ...)`                               |
| **Named Type**       | `@Name` or `@NS::Name`        | `"@Point"`, `"@UI::User"`      | `typedef struct Point {...}`                             |
| **Named Argument**   | `<name>:<type>`               | `"(count:int, data:*void)"`    | (For reflection only)                                    |

### 2.3 Syntax Showcase

| FFI Signature                             | Breakdown                                                                       |
| :---------------------------------------- | :------------------------------------------------------------------------------ |
| `int`                                     | A standard C signed integer.                                                    |
| `*char`                                   | A pointer to a C `signed char`.                                                 |
| `**void`                                  | A pointer to a generic `void` pointer.                                          |
| `[16:char]`                               | An array of 16 signed characters.                                               |
| `*[16:char]`                              | A pointer to an array of 16 signed characters.                                  |
| `{int, float}`                            | An anonymous struct containing an `int` followed by a `float`.                  |
| `{id:uint64, score:double}`               | An anonymous struct with two named fields for introspection.                    |
| `!{id:uint16, status:char}`               | A packed struct (1-byte alignment). `status` will be at offset 2.               |
| `!4:{a:char, b:longlong}`                 | A packed struct with 4-byte alignment. `b` will be padded to start at offset 4. |
| `<int, float64>`                          | An anonymous union that can hold either an `int` or a 64-bit float.             |
| `() -> void`                              | A function that takes no arguments and returns nothing.                         |
| `(*char, int) -> int`                     | A function that takes a `*char` and an `int`, and returns an `int`.             |
| `(*char; int, double) -> int`             | A variadic function like `printf`. The semicolon `;` marks the variadic part.   |
| `*((int, int) -> int)`                    | A pointer to a function that takes two `int`s and returns an `int`.             |
| `{@Point, callback:*((int)->void)}`       | A struct with a named type `@Point` and a function pointer field.               |
| `c[float]`                                | A C `float _Complex` number.                                                    |
| `float16`                                 | A 16-bit half-precision floating-point number.                                  |
| `v[4:float]`                              | A 128-bit SIMD vector of four 32-bit floats (e.g., `__m128` on x86, `float32x4_t` on ARM NEON). |
| `v[8:double]`                             | A 512-bit SIMD vector of eight 64-bit doubles (e.g., `__m512d` on x86 AVX-512). |
| `m256d`                                   | An alias for `v[4:double]`, an AVX vector of 4 `double`s (`__m256d`).           |
| `m512d`                                   | An alias for `v[8:double]`, an AVX-512 vector of 8 `double`s (`__m512d`).       |

#### 2.4 Bitfields and Flexible Arrays

*   **Bitfields:** Bitfields are defined by appending a colon and a bit-width to a struct member's type. They are only valid within `struct` definitions.
    *   **Syntax:** `name : type : width`
    *   **Example:** `!{ flags : uint16 : 3, mode : uint16 : 5 }`
    *   **Zero-width:** `pad : uint32 : 0` forces alignment to the next boundary of the type.

*   **Flexible Array Members (FAM):** A Flexible Array Member must be the *last* member of a struct. It is represented as an array with no size.
    *   **Syntax:** `name : [ ? : type ]` (Note the size before the colon is represented with a question mark (`?`)).
    *   **Example:** `{ len : int, data : [ ? : char ] }`

### 2.5 Scope and Namespaces

`infix` supports C++-style namespaces and nested scopes using the `::` operator. This is used in the Type Registry to define types that live within a namespace, and it is recognized by the C++ mangling dialects to generate correct ABI-compliant symbols.

*   **Example:** `@Graphics::Math::Vector3`

---

## Part 3: The Named Type Registry

The registry is the key to managing complexity in large FFI projects. It provides a central, reusable, and readable way to define and use structs, unions, and type aliases.

### Defining Types (`infix_register_types`)

You populate a registry by passing a string of semicolon-separated definitions. The parser is robust and handles forward declarations and out-of-order definitions automatically.

**Syntax:** `@TypeName = <TypeDefinition>;`

```c
infix_registry_t* registry = infix_registry_create();

const char* my_types =
    // Create readable aliases for any type.
    "@UserID = uint64;"
    "@CallbackFunc = (int)->void;"
    "@Handle = *void;"

    // Define a struct using an alias.
    "@User = { id: @UserID, name: *char };"

    // Define a recursive linked-list node.
    "@Node = { value: int, next: *@Node };"

    // Define mutually recursive types using forward declarations.
    "@A;"
    "@B;"
    "@A = { b_ptr: *@B };"
    "@B = { a_ptr: *@A };"
;

infix_status status = infix_register_types(registry, my_types);
```

**Rule:** Redefining a type that already exists in a registry is an error. Once a name is defined, it is immutable for the lifetime of the registry.

### Using Named Types

Once registered, you can use named types in any signature string by passing the registry handle to the FFI creation function. This works for simple aliases as well as complex structs.

```c
// Using the registry from the example above:
const char* signature = "(*@User, @CallbackFunc) -> void";

infix_forward_t* trampoline = NULL;
infix_forward_create(&trampoline, signature, my_func, registry);
```

When you inspect a type created from an alias (e.g., `@UserID`), you can retrieve its semantic name using `infix_type_get_name()` while still accessing its underlying structural properties (size, alignment, category).

---

## Part 4: Technical Specification

#### 4.1 Whitespace and Comments
Insignificant whitespace (spaces, tabs, newlines) is permitted between any two tokens and should be ignored. Comments begin with a hash symbol (`#`) and continue to the end of the line.

#### 4.2 EBNF Grammar

This Extended Backus-Naur Form grammar formally defines the signature format.

```ebnf
signature           ::= function_type | value_type
value_type          ::= pointer_type | array_type | aggregate_type | enum_type | complex_type | vector_type | primitive_type | grouped_type | named_type_ref

pointer_type        ::= '*' value_type
array_type          ::= '[' Integer ':' value_type ']'
grouped_type        ::= '(' value_type ')'

aggregate_type      ::= struct_type | union_type | packed_struct_type
struct_type         ::= '{' member_list? '}'
packed_struct_type  ::= '!' ( Integer ':' )? '{' member_list? '}'
union_type          ::= '<' member_list? '>'
member_list         ::= member ( ',' member )*
member              ::= ( Identifier ':' )? value_type

enum_type           ::= 'e' ':' primitive_type
complex_type        ::= 'c' '[' value_type ']'
vector_type         ::= 'v' '[' Integer ':' value_type ']'
named_type_ref      ::= '@' Identifier

function_type       ::= '(' arg_list? ')' '->' value_type
arg_list            ::= fixed_args ( ';' variadic_args )? | (';')? variadic_args
fixed_args          ::= arg ( ',' arg )*
variadic_args       ::= arg ( ',' arg )*
arg                 ::= ( Identifier ':' )? value_type

primitive_type      ::= 'void' | 'bool'
                    | 'char' | 'uchar' | 'short' | 'ushort' | 'int' | 'uint'
                    | 'long' | 'ulong' | 'longlong' | 'ulonglong'
                    | 'float' | 'double' | 'longdouble'
                    | 'sint8' | 'uint8' | 'sint16' | 'uint16' | 'sint32' | 'uint32'
                    | 'sint64' | 'uint64' | 'sint128' | 'uint128'
                    | 'float32' | 'float64'
                    | 'm256' | 'm256d' | 'm512' | 'm512d' | 'm512i'

Identifier          ::= ([a-zA-Z_] [a-zA-Z0-9_]*) ( '::' [a-zA-Z_] [a-zA-Z0-9_]* )*
Integer             ::= [0-9]+
```

#### 4.3 Design Rationale: Why This Syntax?

1.  **Readability over Brevity:** The two-tier type system (`int` vs. `int32`) directly maps to developer intent ("portability" vs. "specific layout").
2.  **Unambiguous Grammar:** Using a pure prefix for pointers (`*`) and clear delimiters for all other composites (`[]`, `{}`, `<>`) eliminates ambiguity and allows for simple, linear parsing.
3.  **Consistency:** The `c[...]` and `v[...]` syntax for complex and vector types creates a consistent "family" of specialized numeric constructors.

#### 4.4 Comparison with Other Systems

*   **vs. Itanium C++ ABI:** Itanium is a "write-only" format designed for linkers. `infix` signatures are designed for humans to read and write. The library includes built-in "dialects" to transform these human-readable strings into standard C++ mangled symbols. This allows developers to resolve C++ functions dynamically without manually calculating complex mangled names.
*   **vs. Python's `ctypes`:** `ctypes` uses a programmatic, object-oriented approach. The `infix` format is a standalone, declarative string that can be used by *any* language.
*   **vs. `dyncall`'s Signature Format:** `dyncall`'s format is a flat string of single characters (e.g., `isL)d`), prioritizing brevity. `infix` prioritizes human readability (`(int, ushort, longlong) -> double`). Further, `dyncall` handles aggregate types programmatically via a separate `DCaggr` API, whereas `infix` treats complex data structures as first-class citizens *within the signature string itself*, making the call site much more declarative.
