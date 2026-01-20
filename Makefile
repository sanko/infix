#
# Unified GNU Makefile for infix FFI Library
# Works for native builds on POSIX (Linux, macOS) and Windows (MinGW/MSYS2).
#

CC       := gcc
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
    VECTOR_FLAGS := -msse2 -mavx2 -mavx512f
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
else
    # Native POSIX (Linux, macOS, BSD) Configuration
    EXE_EXT      :=
    LRT_FLAG     := $(shell printf '#include <sys/mman.h>\n#include <fcntl.h>\nint main() { shm_open("", 0, 0); return 0; }' > .check_lrt.c; if $(CC) .check_lrt.c -o .check_lrt.out -lrt >/dev/null 2>&1; then printf -- "-lrt"; fi; rm -f .check_lrt.c .check_lrt.out)
    ifeq ($(LRT_FLAG),-lrt)
        $(info Linker check: -lrt is required and will be added.)
    endif
    LDFLAGS      := -lpthread $(LRT_FLAG) -ldl
    LIB_TARGET   := libinfix.a
    CLEAN_CMD    := rm -f
endif

# Finalize Source and Object Lists
LIB_SRCS := $(BASE_SRCS)
LIB_OBJS := $(LIB_SRCS:.c=.o)

TEST_SRCS   := $(wildcard t/*.c)
TEST_TARGETS:= $(patsubst %.c,%$(EXE_EXT),$(TEST_SRCS))

# Target-Specific Variables for Special Test Cases
# Define extra source files and flags needed ONLY for the regression test.
t/850_regression_cases$(EXE_EXT)_EXTRA_SRCS := fuzz/fuzz_helpers.c
t/850_regression_cases$(EXE_EXT)_EXTRA_CFLAGS := -Ifuzz

# Build Targets
.PHONY: all test clean

# Default target: Build only the static library.
all: $(LIB_TARGET)
	@echo
	@echo "Library '$(LIB_TARGET)' built successfully."

# Test target: Build all test executables, then run them using the embedded Perl script.
test: $(TEST_TARGETS)
	@echo
	@echo "--> Running All Tests"
	@$(PERL) -e 'my $$failures = 0; foreach my $$exe (@ARGV) { print "  > Running $$exe\n"; my $$exit_code = system(".\\" . $$exe); if ($$exit_code != 0) { print "FAILURE: $$exe failed.\n"; $$failures++; } } if ($$failures > 0) { print "\nSUMMARY: $$failures test(s) failed.\n"; exit 1; } else { print "\nAll tests passed.\n"; }' $(TEST_TARGETS)

# Rule to build the static library
$(LIB_TARGET): $(LIB_OBJS)
	@echo "AR  $@"
	$(AR) $(ARFLAGS) $@ $^

# Generic pattern rule to build a test executable.
# It uses automatic variables like `$@` (the target) and `$<` (the first prerequisite)
# and also checks for our target-specific variables.
$(TEST_TARGETS): %$(EXE_EXT): %.c $(LIB_TARGET)
	@echo "LD  $@"
	$(CC) $(TEST_CFLAGS) $($(@)_EXTRA_CFLAGS) $< $($(@)_EXTRA_SRCS) -o $@ -L. -linfix $(LDFLAGS)

# Generic rule to compile library .c files to .o files, using LIB_CFLAGS
%.o: %.c
	@echo "CC  $<"
	$(CC) $(LIB_CFLAGS) -c $< -o $@

# Clean up build artifacts
clean:
	@echo "CLEAN"
	-$(CLEAN_CMD) $(subst /,\,$(LIB_OBJS))
	-$(CLEAN_CMD) $(subst /,\,$(TEST_TARGETS))
	-$(CLEAN_CMD) $(subst /,\,$(LIB_TARGET))
	-rm -f .check_lrt.out
