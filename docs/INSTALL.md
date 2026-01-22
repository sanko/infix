# Building and Integrating infix

This guide shows you how to build the `infix` library and add it to your C projects.

## Prerequisites

You will need a C17-compatible compiler:
*   GCC 8+
*   Clang 7+
*   Visual Studio 2019+

For convenience, a build system is recommended:
*   [perl](https://perl.org) (Recommended)
*   [xmake](https://xmake.io)
*   [CMake](https://cmake.org/download/) 3.12+
*   Make (GNU or NMake)

---

## 1. The Easiest Way: Add `infix` Directly to Your Project

The simplest way to use `infix` is to compile it directly into your project. This "unity build" approach requires no separate build steps and allows for better compiler optimizations.

1.  Copy the `src/` and `include/` directories from the `infix` repository into your project (e.g., into a `third_party/infix` subdirectory).
2.  Add `third_party/infix/src/infix.c` to your list of source files to be compiled.
3.  Add the path to the `include` directory to your compiler's include search paths (e.g., `-Ithird_party/infix/include`).

> That's it. Your project will now build with the `infix` library compiled directly in.

---

## 2. Building `infix` as a Standalone Library (Optional)

If you prefer to build `infix` as a separate static library (`.a` or `.lib`) for system-wide installation or use with tools like `pkg-config`, follow the instructions for your preferred build system.

### Using perl (Recommended)

I personally use the perl based build script to develop, test, and fuzz `infix`. From the root of the `infix` project:

```bash
# Build the library
perl build.pl

# Run tests
perl build.pl test
```

### Using xmake

xmake provides an equally simple, cross-platform build experience. From the root of the `infix` project:

```bash
# Build the library
xmake

# Run tests
xmake test
```

### Using CMake

CMake can generate native build files for your environment (e.g., Makefiles, Visual Studio solutions).

```bash
# Configure the project in a 'build' directory
cmake -B build

# Compile the library
cmake --build build

# Run tests
ctest --test-dir build

# Install the library and headers (may require sudo)
cmake --install build
```

To install to a custom location, use `-DCMAKE_INSTALL_PREFIX=/path/to/install` during the configure step.

### Using Makefiles

**GNU Make (Linux, macOS):**
```bash
make
make test
sudo make install
```

**NMake (Windows with MSVC):**
Open a Developer Command Prompt and run:
```bash
nmake /f Makefile.win
```

### Symbol Visibility

When building `infix` as a shared library (DLL/.so), you must ensure that only the public API is exported.

**Windows (DLL):**
*   **Building:** You **must** define `INFIX_BUILDING_DLL` when compiling the library. This ensures that `__declspec(dllexport)` is applied only to public API functions, preventing internal symbols from polluting the DLL export table.
*   **Using:** You **must** define `INFIX_USING_DLL` when compiling code that links against the `infix` DLL. This applies `__declspec(dllimport)` to the function declarations.

**Linux/macOS:**
All public functions are marked with `INFIX_API` (default visibility). Internal functions are marked with `INFIX_INTERNAL` (hidden visibility). The provided build scripts automatically set `-fvisibility=hidden` to ensure `INFIX_INTERNAL` works as intended.

**Static Library:**
Do not define `INFIX_BUILDING_DLL` or `INFIX_USING_DLL`. This is the default.

The provided build scripts (perl, xmake, CMake, Makefiles) handle these definitions automatically when you select a shared library build.

### Advanced Methods

For minimal environments or direct embedding, you can compile the library manually. The Perl-based builder is also available for advanced development tasks. For details, see the original `INSTALL.md`.

---

## 3. Linking Against a Pre-Built Library

Once `infix` is built and installed, you can link it into your application.

### Using CMake with `find_package`

If you installed `infix` to a standard or custom location, you can use `find_package` in your `CMakeLists.txt`:

```cmake
# Find the installed infix library.
# If installed to a custom path, run cmake with:
# cmake -DCMAKE_PREFIX_PATH=/path/to/your/install ..
find_package(infix REQUIRED)

# Link your application against the imported target.
target_link_libraries(my_app PRIVATE infix::infix)
```

### Using pkg-config

A `infix.pc` file is generated for use with `pkg-config`, which is useful in Makefiles or autotools projects.

```makefile
CFLAGS = `pkg-config --cflags infix`
LIBS = `pkg-config --libs infix`

my_app: main.c
    $(CC) -o my_app main.c $(CFLAGS) $(LIBS)
```

### Using xmake

If you are using xmake for your project, you can add `infix` as a dependency in your `xmake.lua`.

```lua
-- Tell xmake where to find the infix project
add_requires("infix", {git = "https://github.com/sanko/infix.git"})

-- Link your application against the "infix" library
target("my_app")
    set_kind("binary")
    add_files("src/*.c")
    add_deps("infix")
```

### Example: Visual Studio Code Configuration

If you've added the `infix` source to a subdirectory (e.g., `libs/infix`), you can configure VS Code's IntelliSense and build tasks.

**`.vscode/c_cpp_properties.json`** (for IntelliSense)
```json
{
    "configurations": [
        {
            "name": "Linux",
            "includePath": [
                "${workspaceFolder}/**",
                "${workspaceFolder}/libs/infix/include" // <-- Path to infix headers
            ],
            "cStandard": "c17"
        }
    ]
}
```

**`.vscode/tasks.json`** (for Building)
```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "build with infix",
            "type": "shell",
            "command": "gcc",
            "args": [
                "-std=c17", "-g", "${file}",
                "-I${workspaceFolder}/libs/infix/include",   // Find infix headers
                "-L${workspaceFolder}/libs/infix/build",     // Find libinfix.a
                "-linfix",                                  // Link the library
                "-o", "${fileDirname}/${fileBasenameNoExtension}"
            ]
        }
    ]
}
```
