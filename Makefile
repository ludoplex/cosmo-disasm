# cosmo-disasm Makefile
# Builds a cross-platform disassembler library using Cosmopolitan Libc
#
# Usage:
#   make              - Build static library and test program
#   make lib          - Build static library only
#   make test         - Build and run tests
#   make clean        - Remove build artifacts
#   make install      - Install to PREFIX (default: /opt/cosmo)

# Cosmopolitan compiler (assumes cosmocc is in PATH)
CC = cosmocc
AR = cosmoar
CFLAGS = -Wall -Wextra -O2 -I$(SRCDIR) -Iinclude

# Directories
SRCDIR = src
BUILDDIR = build
TESTDIR = test

# Source files
SRCS = $(SRCDIR)/cosmo_disasm.c \
       $(SRCDIR)/cosmo_disasm_x86.c \
       $(SRCDIR)/cosmo_disasm_arm64.c

OBJS = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SRCS))

# Library output
LIB = $(BUILDDIR)/libcosmo_disasm.a

# Test program
TEST_SRC = $(TESTDIR)/test_disasm.c
TEST_PROG = $(BUILDDIR)/test_disasm.com

# Install prefix
PREFIX ?= /opt/cosmo

.PHONY: all lib test clean install dirs

all: dirs lib $(TEST_PROG)

dirs:
	@mkdir -p $(BUILDDIR) $(TESTDIR)

lib: dirs $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_PROG): $(TEST_SRC) $(LIB)
	$(CC) $(CFLAGS) $< -L$(BUILDDIR) -lcosmo_disasm -o $@

test: $(TEST_PROG)
	@echo "Running tests..."
	./$(TEST_PROG)

clean:
	rm -rf $(BUILDDIR)

install: lib
	install -d $(PREFIX)/lib $(PREFIX)/include
	install -m 644 $(LIB) $(PREFIX)/lib/
	install -m 644 include/cosmo_disasm.h $(PREFIX)/include/

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: all

# Windows-specific targets
ifeq ($(OS),Windows_NT)
    # Use PowerShell mkdir on Windows
    dirs:
		@if not exist $(BUILDDIR) mkdir $(BUILDDIR)
		@if not exist $(TESTDIR) mkdir $(TESTDIR)
    clean:
		@if exist $(BUILDDIR) rmdir /s /q $(BUILDDIR)
endif
