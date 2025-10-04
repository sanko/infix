# Building and Integrating `infix`

This guide provides detailed instructions for building the `infix` library from source and integrating it into your own projects. `infix` is designed to be easy to compile and supports several popular build systems.

## Prerequisites

To build `infix`, you will need:

*   A **C17-compatible compiler**, such as:
    *   GCC (version 8 or newer)
    *   Clang (version 7 or newer)
    *   Microsoft Visual C++ (Visual Studio 2019 or newer)
*   One of the following **build systems** (optional, but recommended):
    *   [CMake](https://cmake.org/download/) (version 3.12 or newer)
    *   [xmake](https://xmake.io/#/guide/installation)
    *   GNU Make (for Linux/macOS) or NMake (for Windows)
    *   Perl v5.40+ (includes support for the fuzzers and other advanced developer stuff)

---

## 1. Building `infix` from Source

Choose the build system that best fits your environment.

### Using xmake (Recommended)

xmake is the recommended build system for most platforms as it provides a simple, cross-platform build experience.

1.  **Build:**

    ```bash
    xmake
    ```

2.  **Run Tests:**

    ```bash
    xmake test
    ```

Now, you can simply include the header (`#include <infix.h>`) in your source files and build your project with `xmake`.

### Using Perl

This is what I use to develop `infix` itself but it might be great for just building the lib without installing cmake or xmake. Perl is everywhere!*

```bash
# Run the advanced perl based builder
perl build.pl help

# Build and run valgrind tests
perl build.pl --verbose memtest:fault

# Build infix for another ABI than the current machine's
# Great for fuzzing
perl build.pl --abi=sysv_x64 build
```

### Using CMake

CMake can generate native build files for your environment (e.g., Makefiles on Linux, Visual Studio solutions on Windows).

**Standard Build & Install:**

1.  **Configure:** From the root of the `infix` project, run CMake to generate the build files in a `build` directory.

    ```bash
    # Creates a 'build' directory and prepares it for compilation
    cmake -B build
    ```

2.  **Build:** Compile the library using the generated files.

    ```bash
    # Compiles libinfix.a (or infix.lib on Windows) inside the 'build' directory
    cmake --build build
    ```

3. **Test:** Run the compiled unit tests.

    ```bash
    # Verify
    ctest --test-dir build
    ```

4.  **Install:** Install the library and headers to the location specified by `CMAKE_INSTALL_PREFIX`.

    ```bash
    # Installs headers to /usr/local/include, library to /usr/local/lib, etc.
    # On Linux/macOS, you may need sudo.
    cmake --install build
    ```

**Custom Install Location:**

To install `infix` to a custom directory (e.g., inside your project), use the `CMAKE_INSTALL_PREFIX` option during the configure step.

```bash
# Configure to install into a 'local_install' directory within the project
cmake -B build -DCMAKE_INSTALL_PREFIX=./local_install

# Build and install as before
cmake --build build
cmake --install build
```

### Using Makefiles

#### GNU Make (Linux, macOS, BSDs)

A standard Makefile is provided for POSIX-like systems.

1.  **Build:**

    ```bash
    make
    ```

2.  **Run Tests:**

    ```bash
    make test
    ```

3.  **Install:**

    ```bash
    # This usually requires root privileges
    sudo make install
    ```

#### NMake (Windows with MSVC)

If you are using Microsoft Visual C++, open a **Developer Command Prompt for VS** and use `nmake`.

1.  **Build:**

    ```bash
    nmake /f Makefile.win
    ```

### Manual Compilation (Advanced)

Since `infix` uses a unity build, you can compile it into a static library with a single command. This is useful for minimal environments or for embedding directly into another build system.

**On Linux/macOS (GCC/Clang):**

```bash
# 1. Compile the unity build source file into an object file
gcc -c -std=c17 -Iinclude -o infix.o src/infix.c

# 2. Archive the object file into a static library
ar rcs libinfix.a infix.o
```

**On Windows (MSVC):**

```bash
# 1. Compile the unity build source file
cl /c /Iinclude src/infix.c /Foinfix.obj

# 2. Archive into a static library
lib infix.obj /OUT:infix.lib
```

---

## 2. Integrating `infix` into Your Project

After building and installing `infix`, you can link it into your application.

### Using CMake with `find_package`

If you installed `infix` to a standard location, you can use `find_package` in your project's `CMakeLists.txt`.

```cmake
# Your project's CMakeLists.txt
cmake_minimum_required(VERSION 3.12)
project(my_app C)

# Find the installed infix library and its dependencies.
# If you installed to a custom path, add it to CMAKE_PREFIX_PATH.
# e.g., cmake -DCMAKE_PREFIX_PATH=/path/to/your/install ..
find_package(infix REQUIRED)

add_executable(my_app main.c)

# Link your application against the imported infix::infix target.
target_link_libraries(my_app PRIVATE infix::infix)
```

### Using pkg-config

If you installed `infix`, a `infix.pc` file will be available for `pkg-config`. This is useful in Makefiles or for autotools-based projects.

**Example Makefile:**

```makefile
CFLAGS = -std=c17 `pkg-config --cflags infix`
LIBS = `pkg-config --libs infix`

my_app: main.c
    $(CC) $(CFLAGS) -o my_app main.c $(LIBS)
```

### Using xmake

Add `infix` as a dependency in your `xmake.lua`.

```lua
    -- Your project's xmake.lua
    set_project("my_awesome_app")
    set_version("1.0.0")
    set_languages("c17")

    -- 1. Tell xmake where to find the infix project
    add_requires("infix", {git = "https://github.com/sanko/infix.git"})

    -- Define your application's target
    target("my_awesome_app")
        set_kind("binary")
        add_files("src/*.c")

        -- 2. Link against the "infix" static library target
        add_deps("infix")
```

### Using in Visual Studio Code

1.  Place the `infix` source code in a subdirectory of your project (e.g., `libs/infix`).
2.  Build the `infix` static library (e.g., using CMake).
3.  Create a `.vscode` directory in your project root with the following files:

**`c_cpp_properties.json`** (for IntelliSense)

```json
{
    "configurations": [
        {
            "name": "Linux",
            "includePath": [
                "${workspaceFolder}/**",
                "${workspaceFolder}/libs/infix/include" // <-- Path to infix include dir
            ],
            "cStandard": "c17"
        }
    ],
    "version": 4
}
```

**`tasks.json`** (for Building)

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
                "-L${workspaceFolder}/libs/infix/build/lib", // Find libinfix.a
                "-linfix",                                  // Link the library
                "-o", "${fileDirname}/${fileBasenameNoExtension}"
            ],
            "group": { "kind": "build", "isDefault": true }
        }
    ]
}
```

---

## 3. Packaging `infix` (For Maintainers)

### Linux Distributions (DEB/RPM)

The CMake install target is the standard way to integrate with packaging systems. The key is to use the `DESTDIR` environment variable during the install step.

**Example for a Debian `rules` file:**

```makefile
# debian/rules (simplified)
override_dh_auto_configure:
    dh_auto_configure -- -DCMAKE_INSTALL_PREFIX=/usr

override_dh_auto_build:
    dh_auto_build

override_dh_auto_install:
    dh_auto_install --destdir=$(CURDIR)/debian/tmp
```

### xmake Repository

To submit `infix` to the public `xmake-repo`, you would create a `packages/i/infix/xmake.lua` file in a fork of the repository.

```lua
package("infix")
    set_homepage("https://github.com/sanko/infix")
    set_description("A JIT-powered FFI library for C")

    set_urls("https://github.com/sanko/infix/archive/refs/tags/v$(version).zip")

    add_versions("1.0.0", "sha256_hash_of_the_zip_file")

    on_install(function (package)
        os.cp("include", package:installdir())
        local configs = {}
        if package:config("shared") then
            configs.kind = "shared"
        end
        import("package.tools.xmake").install(package, configs)
    end)
```
