#
# Unified GNU Makefile for infix FFI Library
# Works for native builds on POSIX (Linux, macOS) and Windows (MinGW/MSYS2).
#

CC       := gcc
CXX      := g++
AR       := ar
PERL     := perl
ARFLAGS  := rcs
DEBUG    ?= 0 # Default to non-debug build. Override with `make DEBUG=1`

# Default to x86_64 as a safe fallback
ARCH := x86_64
ifeq ($(OS),Windows_NT)
    # On Windows, use the PROCESSOR_ARCHITECTURE environment variable.
    ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
        ARCH := x86_64
    else ifeq ($(PROCESSOR_ARCHITECTURE),ARM64)
        ARCH := aarch64
    endif
else
    # On POSIX-like systems, `uname -m` is reliable.
    ARCH := $(shell uname -m)
endif

# Base flags for all compilations
BASE_CFLAGS  := -std=c17 -Wall -Wextra -g -O2 -fvisibility=hidden

# Add debug flag if DEBUG=1 is passed on the command line
ifeq ($(DEBUG),1)
    BASE_CFLAGS += -DINFIX_DEBUG_ENABLED=1
    $(info Compiling with debug features enabled.)
endif

# Include directories needed for the LIBRARY
LIB_INC_DIRS := -Iinclude -Isrc -Isrc/arch/x64 -Isrc/arch/aarch64

# Flags for compiling the LIBRARY ONLY. No test flags here.
LIB_CFLAGS   := $(BASE_CFLAGS) $(LIB_INC_DIRS)

# Vector-specific flags for tests
VECTOR_FLAGS :=
ifeq ($(findstring x86_64,$(ARCH)),x86_64)
    VECTOR_FLAGS := -msse2 -mavx2
endif
ifeq ($(findstring aarch64,$(ARCH)),aarch64)
    VECTOR_FLAGS := -march=armv8-a+sve
endif
ifeq ($(findstring arm64,$(ARCH)),arm64)
    VECTOR_FLAGS := -march=armv8-a+sve
endif

# Flags for compiling and linking TESTS ONLY.
# Note: double_tap.h is in src/common, so src needs to be in the include path.
TEST_CFLAGS  := $(BASE_CFLAGS) $(LIB_INC_DIRS) $(VECTOR_FLAGS) -It/include -DDBLTAP_ENABLE=1

# Source Files
BASE_SRCS := src/infix.c

# OS-Specific Configuration
ifeq ($(OS),Windows_NT)
    # Windows Native (MinGW/MSYS2) Configuration
    EXE_EXT      := .exe
    LIB_TARGET   := libinfix.a
    LDFLAGS      := -lkernel32
    CLEAN_CMD    := del /F /Q
    EXPORT_FLAGS := -Wl,--export-all-symbols
    SO_EXT       := dll
else
    # Native POSIX (Linux, macOS, BSD) Configuration
    EXE_EXT      :=
    LRT_FLAG     := $(shell printf '#include <sys/mman.h>\n#include <fcntl.h>\nint main() { shm_open(\"\", 0, 0); return 0; }' > .check_lrt.c; if $(CC) .check_lrt.c -o .check_lrt.out -lrt >/dev/null 2>&1; then printf -- "-lrt"; fi; rm -f .check_lrt.c .check_lrt.out)
    ifeq ($(LRT_FLAG),-lrt)
        $(info Linker check: -lrt is required and will be added.)
    endif
    LDFLAGS      := -lpthread $(LRT_FLAG) -ldl -lm
    LIB_TARGET   := libinfix.a
    CLEAN_CMD    := rm -f
    EXPORT_FLAGS := -rdynamic
    SO_EXT       := so
endif

# Finalize Source and Object Lists
LIB_SRCS := $(BASE_SRCS)
LIB_OBJS := $(LIB_SRCS:.c=.o)
SHARED_LIB_OBJS := $(LIB_SRCS:.c=.shared.o)

TEST_SRCS   := $(wildcard t/*.c) $(wildcard t/*.cpp)
TEST_TARGETS:= $(patsubst t/%.c,t/%$(EXE_EXT),$(filter %.c,$(TEST_SRCS)))
TEST_TARGETS+= $(patsubst t/%.cpp,t/%$(EXE_EXT),$(filter %.cpp,$(TEST_SRCS)))

# Target-Specific Variables for Special Test Cases
# Define extra source files and flags needed ONLY for the regression test.
t/850_regression_cases$(EXE_EXT)_EXTRA_SRCS := fuzz/fuzz_helpers.c
t/850_regression_cases$(EXE_EXT)_EXTRA_CFLAGS := -Ifuzz

# 880_exports needs to export its own symbols to test dlsym(NULL)
t/880_exports$(EXE_EXT)_EXTRA_LDFLAGS := $(EXPORT_FLAGS)

# Build Targets
.PHONY: all test clean shared

# Default target: Build only the static library.
all: $(LIB_TARGET)
	@echo
	@echo "Library '$(LIB_TARGET)' built successfully."

# Shared library target
shared: libinfix.$(SO_EXT)
	@echo
	@echo "Shared Library 'libinfix.$(SO_EXT)' built successfully."

# Test target: Build all test executables, then run them using the embedded Perl script.
test: $(TEST_TARGETS)
	@echo
	@echo "--> Running All Tests"
	@$(PERL) -e 'my $$failures = 0; foreach my $$exe (@ARGV) { print "  > Running $$exe\n"; my $$exit_code = system("./" . $$exe); if ($$exit_code != 0) { print "FAILURE: $$exe failed.\n"; $$failures++; } } if ($$failures > 0) { print "\nSUMMARY: $$failures test(s) failed.\n"; exit 1; } else { print "\nAll tests passed.\n"; }' $(TEST_TARGETS)

# Rule to build the static library
$(LIB_TARGET): $(LIB_OBJS)
	@echo "AR  $@"
	$(AR) $(ARFLAGS) $@ $^

# Rule to build the shared library
libinfix.$(SO_EXT): $(SHARED_LIB_OBJS)
	@echo "LD  $@"
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# Generic pattern rule to build a C test executable.
t/%$(EXE_EXT): t/%.c $(LIB_TARGET)
	@echo "LD (C)  $@"
	$(CC) $(TEST_CFLAGS) $($(@)_EXTRA_CFLAGS) $< $($(@)_EXTRA_SRCS) -o $@ -L. -linfix $(LDFLAGS) $($(@)_EXTRA_LDFLAGS)

# Generic pattern rule to build a C++ test executable.
t/%$(EXE_EXT): t/%.cpp $(LIB_TARGET)
	@echo "LD (C++) $@"
	$(CXX) $(TEST_CFLAGS) $($(@)_EXTRA_CFLAGS) $< $($(@)_EXTRA_SRCS) -o $@ -L. -linfix $(LDFLAGS) $($(@)_EXTRA_LDFLAGS)

# Generic rule to compile library .c files to .o files, using LIB_CFLAGS
%.o: %.c
	@echo "CC  $<"
	$(CC) $(LIB_CFLAGS) -c $< -o $@

# Rule to compile for shared library (with -fPIC and -DINFIX_BUILDING_DLL)
%.shared.o: %.c
	@echo "CC (Shared) $<"
	$(CC) $(LIB_CFLAGS) -fPIC -DINFIX_BUILDING_DLL -c $< -o $@

# Clean up build artifacts
clean:
	@echo "CLEAN"
	-$(CLEAN_CMD) $(subst /uyễn,uyễn,$(LIB_OBJS))
	-$(CLEAN_CMD) $(subst /uyễn,uyễn,$(SHARED_LIB_OBJS))
	-$(CLEAN_CMD) $(subst /uyễn,uyễn,$(TEST_TARGETS))
	-$(CLEAN_CMD) $(subst /uyễn,uyễn,$(LIB_TARGET))
	-$(CLEAN_CMD) libinfix.so libinfix.dll infix.dll infix.lib infix.exp
	-rm -f .check_lrt.out
