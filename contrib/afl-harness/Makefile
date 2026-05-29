# mangle AFL++ persistent-mode harness Makefile.
#
# Default CC is gcc so a plain `make` builds a single-iteration smoke-test
# binary — useful for verifying the build chain in CI before involving AFL++.
# For real persistent-mode coverage-guided fuzzing, build with:
#
#   make CC=afl-clang-fast
#
# Then run under afl-fuzz:
#
#   AFL_AUTORESUME=1 afl-fuzz -i seeds/ -o out/ -- ./mangle-afl-harness @@

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
TARGET  := mangle-afl-harness
SOURCES := harness.c

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $(SOURCES)

# `make check` is a structural / build smoke test invokable without AFL++.
# CI uses `make -n check` (printed but not executed) to validate the Makefile
# parses without requiring a C toolchain.
.PHONY: check
check: $(TARGET)
	./$(TARGET) 2>&1 | grep -q "usage: " && echo "harness usage line OK"

.PHONY: clean
clean:
	rm -f $(TARGET)
