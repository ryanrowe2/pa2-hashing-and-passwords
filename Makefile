CC = cc
CPPFLAGS = -Iinclude
CFLAGS = -std=c11 -O2 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes -Werror
LDFLAGS =
LDLIBS = -lcrypto
BIN = build/pwcrack
UNIT = build/test_core
FAULT = build/test_fault
FAULT_CLI = build/pwcrack_sha_error
CONFIG = build/.build-config
SAN_FLAGS = -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer

ifeq ($(SANITIZE),1)
CFLAGS += $(SAN_FLAGS)
LDFLAGS += -fsanitize=address,undefined
endif

.DELETE_ON_ERROR:

.PHONY: all clean test bench analyze FORCE
all: $(BIN)

build:
	mkdir -p build

# Rebuild when compiler or effective flags change, even without source edits.
# Only replace the config stamp if its contents actually differ.
$(CONFIG): FORCE | build
	@printf '%s\n' 'CC=$(CC)' 'CPPFLAGS=$(CPPFLAGS)' 'CFLAGS=$(CFLAGS)' 'LDFLAGS=$(LDFLAGS)' 'LDLIBS=$(LDLIBS)' > $@.tmp
	@if ! cmp -s $@.tmp $@; then mv $@.tmp $@; else rm $@.tmp; fi

FORCE:

# Atomic builds: never publish a partial executable after compilation fails.
# The temporary binary is kept in the destination directory for atomic rename.
define compile_atomically
	@set -eu; \
		tmp="$@.tmp.$$"; \
		trap 'rm -f "$tmp"' EXIT HUP INT TERM; \
		printf 'Compiling %s with %s (flags: %s)\n' "$@" "$(CC)" "$(CFLAGS)"; \
		$(CC) $(CPPFLAGS) $(CFLAGS) $(1) $(LDFLAGS) $(2) $(LDLIBS) -o "$tmp"; \
		mv -f "$tmp" "$@"
endef

$(BIN): src/main.c src/pwcrack.c include/pwcrack.h Makefile $(CONFIG) | build
	$(call compile_atomically,src/main.c src/pwcrack.c,)

$(UNIT): tests/test_core.c src/pwcrack.c include/pwcrack.h Makefile $(CONFIG) | build
	$(call compile_atomically,tests/test_core.c src/pwcrack.c,)

$(FAULT): tests/test_fault.c src/pwcrack.c include/pwcrack.h Makefile $(CONFIG) | build
	$(call compile_atomically,tests/test_fault.c src/pwcrack.c,-Wl,--wrap=SHA256)

$(FAULT_CLI): tests/sha256_fail.c src/main.c src/pwcrack.c include/pwcrack.h Makefile $(CONFIG) | build
	$(call compile_atomically,tests/sha256_fail.c src/main.c src/pwcrack.c,-Wl,--wrap=SHA256)

test: $(BIN) $(UNIT) $(FAULT) $(FAULT_CLI)
	./$(UNIT)
	./$(FAULT)
	PWCRACK_BIN=./$(BIN) PWCRACK_FAULT_BIN=./$(FAULT_CLI) python3 -m unittest discover -s tests -p 'test_*.py' -v

bench: $(BIN)
	PWCRACK_BIN=./$(BIN) python3 tests/benchmark.py

analyze:
	@for source in src/main.c src/pwcrack.c; do \
		clang --analyze -std=c11 -Wall -Wextra -Wpedantic -Iinclude -o /dev/null "$$source" || exit $$?; \
	done

clean:
	rm -rf build
