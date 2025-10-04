#
# Unified GNU Makefile for infix FFI Library
# Works for native builds on POSIX (Linux, macOS) and Windows (MinGW/MSYS2).
#

# Default Configuration
CC      := gcc
AR      := ar
ARFLAGS := rcs

# --- Flags ---
# Base flags for all compilations
BASE_CFLAGS  := -std=c17 -Wall -Wextra -g -O2

# Include directories needed for the LIBRARY
LIB_INC_DIRS := -Iinclude -Isrc -Isrc/arch/x64 -Isrc/arch/aarch64

# Flags for compiling the LIBRARY ONLY. No test flags here.
LIB_CFLAGS   := $(BASE_CFLAGS) $(LIB_INC_DIRS) -DINFIX_DEBUG_ENABLED=1

# Flags for compiling and linking TESTS ONLY.
<<<<<<< HEAD
TEST_CFLAGS  := $(BASE_CFLAGS) $(LIB_INC_DIRS) -mavx2 -It/include -Ithird_party/double_tap -DDBLTAP_ENABLE=1 -DINFIX_DEBUG_ENABLED=1
=======
TEST_CFLAGS  := $(BASE_CFLAGS) $(LIB_INC_DIRS) -It/include -Ithird_party/double_tap -DDBLTAP_ENABLE=1 -DINFIX_DEBUG_ENABLED=1
>>>>>>> main

# --- Source Files ---
# The list of library sources is now complete.
BASE_SRCS := src/infix.c

# OS-Specific Configuration
ifeq ($(OS),Windows_NT)
    # Windows Native (MinGW/MSYS2) Configuration
    EXE_EXT      := .exe
    LIB_TARGET   := libinfix.a
    LDFLAGS      := -lkernel32
    CLEAN_CMD    := del /F /Q
    TOUCH        := cmd /C "type NUL >"
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
    TOUCH        := touch
endif

# Finalize Source and Object Lists
LIB_SRCS := $(BASE_SRCS)
LIB_OBJS := $(LIB_SRCS:.c=.o)

TEST_SRCS   := $(wildcard t/*.c)
TEST_TARGETS:= $(patsubst %.c,%$(EXE_EXT),$(TEST_SRCS))
TEST_RESULTS:= $(patsubst %.c,%.passed,$(TEST_SRCS))

# Build Targets
.PHONY: all test clean clean-results

# Default target: Build only the static library.
all: $(LIB_TARGET)
	@echo
	@echo "Library '$(LIB_TARGET)' built successfully."

# Test target: A PHONY target to ensure it always runs.
test: clean-results $(TEST_RESULTS)
	@echo
	@echo "All tests passed."

# A PHONY target to remove old result files.
clean-results:
	-$(CLEAN_CMD) $(subst /,\,$(TEST_RESULTS))

# Pattern rule to create a ".passed" file by running the corresponding test.
%.passed: %$(EXE_EXT)
	@echo
	@echo "==> Running $<"
	./$(subst \,/,$<)
	@$(TOUCH) $@

# Rule to build the static library
$(LIB_TARGET): $(LIB_OBJS)
	@echo "AR  $@"
	$(AR) $(ARFLAGS) $@ $^

# Rule to build any test executable, using TEST_CFLAGS
$(TEST_TARGETS): %$(EXE_EXT): %.c $(LIB_TARGET)
	@echo "LD  $@"
	$(CC) $(TEST_CFLAGS) $< -o $@ -L. -linfix $(LDFLAGS)

# Generic rule to compile library .c files to .o files, using LIB_CFLAGS
%.o: %.c
	@echo "CC  $<"
	$(CC) $(LIB_CFLAGS) -c $< -o $@

# Clean up build artifacts
clean: clean-results
	@echo "CLEAN"
	-$(CLEAN_CMD) $(subst /,\,$(LIB_OBJS))
	-$(CLEAN_CMD) $(subst /,\,$(TEST_TARGETS))
	-$(CLEAN_CMD) $(subst /,\,$(LIB_TARGET))
	-rm -f .check_lrt.out
