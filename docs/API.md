# API Quick Reference

This document provides a concise reference for the public API of the `infix` library. It's designed to be a quick lookup for developers who are already familiar with the library's concepts.

For practical, in-depth examples, please see the [Cookbook](cookbook.md).

## Table of Contents

*   [1. High-Level Signature API](#1-high-level-signature-api)
    *   [Forward Trampolines (Calling C)](#forward-trampolines-calling-c)
    *   [Reverse Trampolines (Callbacks & Closures)](#reverse-trampolines-callbacks--closures)
    *   [Direct Marshalling (Advanced Language Bindings)](#direct-marshalling-advanced-language-bindings)
*   [2. Error Handling API](#2-error-handling-api)
    *   [The Error Handling Pattern](#the-error-handling-pattern)
    *   [Common Error Categories](#common-error-categories)
*   [3. Introspection API](#3-introspection-api)
    *   [Library Version](#library-version)
    *   [Getting Callable Code](#getting-callable-code)
    *   [Inspecting Trampoline Properties](#inspecting-trampoline-properties)
    *   [Inspecting Type Properties](#inspecting-type-properties)
*   [4. Named Type Registry API](#4-named-type-registry-api)
    *   [Creation, Cloning, and Population](#creation-cloning-and-population)
    *   [Registry Introspection & Iteration](#registry-introspection--iteration)
*   [5. Dynamic Library & Globals API](#5-dynamic-library--globals-api)
*   [6. Manual API (Advanced)](#6-manual-api-advanced)
    *   [Manual Trampoline Creation](#manual-trampoline-creation)
    *   [Manual Type Creation](#manual-type-creation)
*   [7. Memory Management (Arenas)](#7-memory-management-arenas)

---

## 1. High-Level Signature API

These are the primary, recommended functions for creating trampolines from human-readable signature strings.

### Forward Trampolines (Calling C)

#### `infix_forward_create`
Creates a high-performance "bound" trampoline compiled for a *specific* C function. This is the fastest way to call the same function repeatedly. This function creates a private memory arena for the trampoline and performs a deep copy of all type metadata, ensuring it is a self-contained object.

```c
infix_status infix_forward_create(
    infix_forward_t** out_trampoline,
    const char* signature,
    void* target_function,
    infix_registry_t* registry
);
```

#### `infix_forward_create_unbound`
Creates a more flexible "unbound" trampoline for a given signature. The target function is provided at call time, allowing you to reuse one trampoline for multiple functions with the same signature. Like `infix_forward_create`, this function creates a private arena for the trampoline.

```c
infix_status infix_forward_create_unbound(
    infix_forward_t** out_trampoline,
    const char* signature,
    infix_registry_t* registry
);
```

#### `infix_forward_create_in_arena` (Advanced)
Creates a "bound" forward trampoline that allocates its internal metadata from a user-provided arena. When the `target_arena` is the same one used by a registry, this function will share pointers to named types instead of deep-copying them, significantly saving memory and improving creation performance.

```c
infix_status infix_forward_create_in_arena(
    infix_forward_t** out_trampoline,
    infix_arena_t* target_arena,
    const char* signature,
    void* target_function,
    infix_registry_t* registry
);
```

### Direct Marshalling (Advanced Language Bindings)

These functions allow creating high-performance trampolines that call user-defined marshallers directly, bypassing intermediate buffers.

#### `infix_forward_create_direct`
Creates a trampoline where the JIT code invokes user-provided callbacks to fetch argument data.

```c
infix_status infix_forward_create_direct(
    infix_forward_t** out_trampoline,
    const char* signature,
    void* target_function,
    infix_direct_arg_handler_t* handlers,
    infix_registry_t* registry
);
```

#### `infix_forward_get_direct_code`
Retrieves the callable pointer for a direct trampoline. The signature of this function pointer is `void (*)(void* ret_buf, void** lang_objs)`.

```c
infix_direct_cif_func infix_forward_get_direct_code(infix_forward_t* trampoline);
```

### Reverse Trampolines (Callbacks & Closures)

#### `infix_reverse_create_callback`
Creates a reverse trampoline for a type-safe C function. This is the easiest way to create a callback for a C library like `qsort`. This function creates a private memory arena for the callback context.

```c
infix_status infix_reverse_create_callback(
    infix_reverse_t** out_context,
    const char* signature,
    void* user_callback_fn,
    infix_registry_t* registry
);
```

#### `infix_reverse_create_closure`
Creates a reverse trampoline with a generic handler. This is the ideal choice for creating stateful callbacks or for language bindings, as it gives you low-level control and a `user_data` pointer to maintain state. This function creates a private memory arena for the closure context.

```c
infix_status infix_reverse_create_closure(
    infix_reverse_t** out_context,
    const char* signature,
    infix_closure_handler_fn user_callback_fn,
    void* user_data,
    infix_registry_t* registry
);
```

---

## 2. Error Handling API

Error handling in `infix` is designed to be both detailed and thread-safe. All detailed error information is stored in thread-local storage, so an error in one thread won't affect another.

### The Error Handling Pattern

The basic pattern is to always check the `infix_status` return value of an API function. If it's anything other than `INFIX_SUCCESS`, you can get more details.

```c
infix_error_details_t infix_get_last_error(void);
```

This function returns a copy of an `infix_error_details_t` struct, which contains everything you need to know about what went wrong:

*   `category`: A high-level category like `INFIX_CATEGORY_PARSER`.
*   `code`: A specific error code like `INFIX_CODE_UNEXPECTED_TOKEN`.
*   `position`: For parser errors, the exact character position in the signature string where the error occurred.
*   `message`: A detailed, human-readable error message.

### Common Error Categories

#### Parser Errors (`INFIX_CATEGORY_PARSER`)
**What it means:** There is a syntax error in a signature string you provided.
**How to handle:** This is the most common type of error. You can use the `position` and `message` from the error details to provide a rich diagnostic to the user, much like a compiler would.

```c
// Example: Handling a parser error
infix_status status = infix_type_from_signature(&type, &arena, "{int, ^double}", NULL);

if (status != INFIX_SUCCESS) {
    infix_error_details_t err = infix_get_last_error();
    fprintf(stderr, "Error parsing signature:\n");
    fprintf(stderr, "  %s\n", "{int, ^double}");
    fprintf(stderr, "  %*s^\n", (int)err.position, ""); // Print a caret
    fprintf(stderr, "Details: %s\n", err.message);
}
```

#### Allocation Errors (`INFIX_CATEGORY_ALLOCATION`)
**What it means:** The library failed to allocate memory, either from the standard heap (`malloc`) or from the OS for executable JIT code (`mmap`/`VirtualAlloc`). This usually means the system is out of memory.
**How to handle:** There is often little you can do to recover. The best course of action is to log the error and terminate the process gracefully.

#### ABI & Layout Errors (`INFIX_CATEGORY_ABI`)
**What it means:** This is a more subtle category of error related to the function's structure.
*   You used a named type (e.g., `@Point`) in a signature but didn't provide a registry, or the name wasn't found.
*   You tried to create an invalid type, like a struct containing a `void` member.
*   A type was too large or complex for the target architecture's ABI to handle (e.g., a struct larger than the maximum safe stack allocation size).
**How to handle:** Double-check your signature strings and type definitions in the registry. Ensure you are passing the correct registry handle to the creation function.

#### General & Library Errors
**What it means:** This is a catch-all for other issues.
*   You passed an invalid argument to an API function (e.g., `NULL` where a valid pointer was required).
*   When using the dynamic library API, the requested library (`.so`, `.dll`) could not be found or a symbol lookup failed.
**How to handle:** For library errors, ensure the shared library file is in the expected location (e.g., the current directory, or a system path). For other errors, review the arguments you are passing to the `infix` function call.

---

## 3. Introspection API

Functions for inspecting the properties of trampolines and types at runtime.

### Library Version

*   `infix_version_t infix_get_version(void)`: Returns the semantic version of the linked library. The returned struct has `.major`, `.minor`, and `.patch` fields.

### Getting Callable Code

*   `infix_cif_func infix_forward_get_code(infix_forward_t* trampoline)`: Gets the callable function pointer from a **bound** forward trampoline.
*   `infix_unbound_cif_func infix_forward_get_unbound_code(infix_forward_t* trampoline)`: Gets the callable function pointer from an **unbound** forward trampoline.
*   `void* infix_reverse_get_code(const infix_reverse_t* context)`: Gets the native C function pointer from a reverse trampoline.
*   `void* infix_reverse_get_user_data(const infix_reverse_t* context)`: Gets the `user_data` pointer from a closure.
*   `infix_direct_cif_func infix_forward_get_direct_code(infix_forward_t* trampoline)`: Gets the callable function pointer from a **direct marshalling** forward trampoline.

### Inspecting Trampoline Properties

These functions work for both `infix_forward_t*` and `infix_reverse_t*` handles.

*   `size_t infix_forward_get_num_args(const infix_forward_t* handle)`: Returns the total number of arguments.
*   `size_t infix_forward_get_num_fixed_args(const infix_forward_t* handle)`: Returns the number of non-variadic arguments.
*   `const infix_type* infix_forward_get_return_type(const infix_forward_t* handle)`: Returns the `infix_type` for the return value.
*   `const infix_type* infix_forward_get_arg_type(const infix_forward_t* handle, size_t index)`: Returns the `infix_type` for the argument at `index`.

*(Note: The `infix_reverse_*` variants have the same function signatures.)*

### Inspecting Type Properties

*   `infix_status infix_type_from_signature(...)`: Parses a signature string into a detailed `infix_type` graph.
*   `const char* infix_type_get_name(const infix_type* type)`: Returns the semantic alias of a type (e.g., "MyInt"), or `NULL` if anonymous.
*   `infix_type_category infix_type_get_category(const infix_type* type)`: Returns the fundamental category (e.g., `INFIX_TYPE_STRUCT`).
*   `size_t infix_type_get_size(const infix_type* type)`: Returns the size of the type in bytes.
*   `size_t infix_type_get_alignment(const infix_type* type)`: Returns the alignment requirement in bytes.
*   `size_t infix_type_get_member_count(const infix_type* type)`: Returns the number of members in a struct or union.
*   `const infix_struct_member* infix_type_get_member(const infix_type* type, size_t index)`: Retrieves a specific member from a struct or union by its index. The returned `infix_struct_member*` gives you access to:
    *   `.name`: The name of the field as a `const char*`.
    *   `.type`: The `infix_type*` of the field.
    *   `.offset`: The field's byte offset from the start of the struct.
*   `infix_status infix_type_print(...)`: Serializes an `infix_type` back into a human-readable string.

---

## 4. Named Type Registry API

APIs for defining, storing, reusing, and inspecting complex types by name.

### Creation, Cloning, and Population

*   `infix_registry_t* infix_registry_create(void)`: Creates a new, empty type registry with an internal, automatically growing memory arena.
*   `infix_registry_t* infix_registry_create_in_arena(infix_arena_t* arena)`: (Advanced) Creates a new registry that allocates from a user-provided arena. This is used for the shared arena optimization pattern.
*   `infix_registry_t* infix_registry_clone(const infix_registry_t* registry)`: Creates a deep copy of an existing registry. The new registry has its own internal arena and copies of all types, making it thread-safe to use independently of the original.
*   `void infix_registry_destroy(infix_registry_t* registry)`: Destroys a registry and all its contents. If the registry was created with an external arena (`infix_registry_create_in_arena`), the user-provided arena itself is **not** freed.
*   `infix_status infix_register_types(infix_registry_t* registry, const char* definitions)`: Parses a semicolon-separated string of type definitions and adds them to the registry. The internal arena will grow automatically if needed.
*   `const infix_type* infix_registry_lookup_type(const infix_registry_t* registry, const char* name)`: Retrieves a fully defined type object by its name.

### Registry Introspection & Iteration

These functions allow you to iterate through all of the fully defined types within a registry.

*   `infix_registry_iterator_t infix_registry_iterator_begin(const infix_registry_t* registry)`: Creates and returns an iterator positioned at the beginning of the registry.
*   `bool infix_registry_iterator_next(infix_registry_iterator_t* iterator)`: Advances the iterator to the next type. It returns `true` if it successfully moved to a valid type, and `false` if there are no more types to visit.
*   `const char* infix_registry_iterator_get_name(const infix_registry_iterator_t* iterator)`: Gets the name of the type at the iterator's current position (e.g., `"Point"`).
*   `const infix_type* infix_registry_iterator_get_type(const infix_registry_iterator_t* iterator)`: Gets the `infix_type` object for the type at the iterator's current position.

---

## 5. Dynamic Library & Globals API

Cross-platform functions for loading shared libraries and accessing exported symbols.

*   `infix_library_t* infix_library_open(const char* path)`: Opens a dynamic library (`.so`, `.dll`).
*   `void infix_library_close(infix_library_t* lib)`: Closes a library handle.
*   `void* infix_library_get_symbol(infix_library_t* lib, const char* symbol_name)`: Retrieves the address of a function or global variable.
*   `infix_status infix_read_global(...)`: Reads the value of a global variable from a library into a buffer.
*   `infix_status infix_write_global(...)`: Writes data from a buffer into a global variable in a library.

---

## 6. Manual API (Advanced)

A lower-level API for creating trampolines from programmatically-built `infix_type` objects, bypassing the string parser.

### Manual Trampoline Creation

These functions mirror the high-level API but take `infix_type` objects instead of signature strings.
*   `infix_status infix_forward_create_manual(...)`
*   `infix_status infix_forward_create_unbound_manual(...)`
*   `infix_status infix_reverse_create_callback_manual(...)`
*   `infix_status infix_reverse_create_closure_manual(...)`

### Trampoline Destruction

All trampolines created by `infix` allocate executable memory and internal metadata that must be explicitly freed when no longer needed.

*   `void infix_forward_destroy(infix_forward_t* trampoline)`: Destroys a forward trampoline.
*   `void infix_reverse_destroy(infix_reverse_t* trampoline)`: Destroys a reverse trampoline.

### Manual Type Creation

These functions are the building blocks for creating `infix_type` objects programmatically. All new types must be allocated from a user-provided arena.

*   `infix_type* infix_type_create_primitive(infix_primitive_type_id id)`: Returns a static descriptor for a primitive type like `int` or `double`. Does not require an arena.
*   `infix_type* infix_type_create_pointer(void)`: Returns a static descriptor for a generic `void*`. Does not require an arena.
*   `infix_type* infix_type_create_void(void)`: Returns the static descriptor for `void`. Does not require an arena.
*   `infix_status infix_type_create_pointer_to(infix_arena_t* arena, ...)`: Creates a new pointer type that points to a specific other type.
*   `infix_status infix_type_create_struct(infix_arena_t* arena, ...)`: Creates a new struct, automatically calculating member offsets and padding.
*   `infix_status infix_type_create_packed_struct(infix_arena_t* arena, ...)`: Creates a struct with a user-specified size, alignment, and member offsets.
*   `infix_status infix_type_create_union(infix_arena_t* arena, ...)`: Creates a new union, calculating its size and alignment based on its members.
*   `infix_status infix_type_create_array(infix_arena_t* arena, ...)`: Creates a new fixed-size array type.
*   `infix_status infix_type_create_enum(infix_arena_t* arena, ...)`: Creates a new enum type with a specified underlying integer type.
*   `infix_status infix_type_create_complex(infix_arena_t* arena, ...)`: Creates a new C99 `_Complex` number type.
*   `infix_status infix_type_create_vector(infix_arena_t* arena, ...)`: Creates a new SIMD vector type.
*   `infix_status infix_type_create_named_reference(infix_arena_t* arena, ...)`: Creates a placeholder for a named type that will be resolved by a registry.
*   `infix_struct_member infix_type_create_member(...)`: A factory function to create a member object for use with `infix_type_create_struct` or `_union`.

---

## 7. Memory Management (Arenas)

APIs for the fast, region-based arena allocator used by the Manual API. The internal arena implementation supports chaining to grow as needed, so you do not need to worry about the initial size for most use cases.

*   `infix_arena_t* infix_arena_create(size_t initial_size)`: Creates a new memory arena.
*   `void infix_arena_destroy(infix_arena_t* arena)`: Destroys an arena and frees all memory allocated from it.
*   `void* infix_arena_alloc(infix_arena_t* arena, size_t size, size_t alignment)`: Allocates a block of memory from an arena.
*   `void* infix_arena_calloc(infix_arena_t* arena, ...)`: Allocates and zero-initializes memory from an arena.
