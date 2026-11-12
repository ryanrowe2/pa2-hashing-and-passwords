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
WRAP_SHA256 = -Wl,--wrap=SHA256
SAN_FLAGS = -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer

ifeq ($(SANITIZE),1)
CFLAGS += $(SAN_FLAGS)
LDFLAGS += -fsanitize=address,undefined
endif

# Inspection modes (-n/--just-print and -q/--question) must not acquire a
# build lock or invoke recipes. GNU Make places compact short switches first
# in MAKEFLAGS; ignore long options and -j arguments when detecting them.
PA2_SHORT_FLAGS := $(filter-out -%,$(firstword $(MAKEFLAGS)))
ifneq ($(findstring n,$(PA2_SHORT_FLAGS))$(findstring q,$(PA2_SHORT_FLAGS)),)
PA2_INSPECTION_MODE := 1
PA2_BUILD_SERIALIZED := 1
endif

# Serialize independent Make processes across all public build entry points.
# Hold the lock over config-stamp updates, compilation and tests, not merely
# individual recipes. Keep the lock outside build/ so clean cannot unlink it.
ifeq ($(PA2_BUILD_SERIALIZED),1)

.DELETE_ON_ERROR:

.PHONY: all clean test bench analyze FORCE
all: $(BIN)

build:
	mkdir -p build

# Rebuild when compiler or effective flags change, even without source edits.
# Only replace the config stamp if its contents actually differ.
# During dry-run/question mode, compare the desired settings read-only:
# unconditional FORCE would incorrectly report a fresh binary as outdated.
ifeq ($(PA2_INSPECTION_MODE),1)
PA2_CONFIG_MATCHES := $(shell test -f '$(CONFIG)' && \
    printf '%s\n' 'CC=$(CC)' 'CPPFLAGS=$(CPPFLAGS)' 'CFLAGS=$(CFLAGS)' 'LDFLAGS=$(LDFLAGS)' 'LDLIBS=$(LDLIBS)' | cmp -s - '$(CONFIG)' && echo yes)
ifeq ($(PA2_CONFIG_MATCHES),yes)
PA2_CONFIG_FORCE :=
else
PA2_CONFIG_FORCE := FORCE
endif
else
PA2_CONFIG_FORCE := FORCE
endif

$(CONFIG): $(PA2_CONFIG_FORCE) | build
	@set -eu; \
		tmp="$@.tmp.$$$$"; \
		trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
		printf '%s\n' 'CC=$(CC)' 'CPPFLAGS=$(CPPFLAGS)' 'CFLAGS=$(CFLAGS)' 'LDFLAGS=$(LDFLAGS)' 'LDLIBS=$(LDLIBS)' > "$$tmp"; \
		if ! cmp -s "$$tmp" "$@"; then mv -f "$$tmp" "$@"; fi

FORCE:

# Atomic builds: never publish a partial executable after compilation fails.
# The temporary binary is kept in the destination directory for atomic rename.
define compile_atomically
	@set -eu; \
		tmp="$@.tmp.$$$$"; \
		trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
		printf 'Compiling %s with %s (flags: %s)\n' "$@" "$(CC)" "$(CFLAGS)"; \
		$(CC) $(CPPFLAGS) $(CFLAGS) $(1) $(LDFLAGS) $(2) $(LDLIBS) -o "$$tmp"; \
		mv -f "$$tmp" "$@"
endef

$(BIN): src/main.c src/pwcrack.c include/pwcrack.h Makefile $(CONFIG) | build
	$(call compile_atomically,src/main.c src/pwcrack.c,)

$(UNIT): tests/test_core.c src/pwcrack.c include/pwcrack.h Makefile $(CONFIG) | build
	$(call compile_atomically,tests/test_core.c src/pwcrack.c,)

$(FAULT): tests/test_fault.c src/pwcrack.c include/pwcrack.h Makefile $(CONFIG) | build
	$(call compile_atomically,tests/test_fault.c src/pwcrack.c,$(WRAP_SHA256))

$(FAULT_CLI): tests/sha256_fail.c src/main.c src/pwcrack.c include/pwcrack.h Makefile $(CONFIG) | build
	$(call compile_atomically,tests/sha256_fail.c src/main.c src/pwcrack.c,$(WRAP_SHA256))

test: $(BIN) $(UNIT) $(FAULT) $(FAULT_CLI)
	./$(UNIT)
	./$(FAULT)
	env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL -u PA2_BUILD_SERIALIZED PWCRACK_BIN=./$(BIN) PWCRACK_FAULT_BIN=./$(FAULT_CLI) python3 -W error::ResourceWarning -m unittest discover -s tests -p 'test_*.py' -v

bench: $(BIN)
	PWCRACK_BIN=./$(BIN) python3 tests/benchmark.py

analyze:
	@for source in src/main.c src/pwcrack.c; do \
		clang --analyze -std=c11 -Wall -Wextra -Wpedantic -Iinclude -o /dev/null "$$source" || exit $$?; \
	done

clean:
	rm -rf build

else

.DEFAULT_GOAL := all

# flock is provided by util-linux on supported Linux builds. The recursive
# Make inherits command-line overrides (CC, CFLAGS, SANITIZE, etc.).
.PHONY: all test bench analyze clean build $(BIN) $(UNIT) $(FAULT) $(FAULT_CLI) $(CONFIG)
all test bench analyze clean build $(BIN) $(UNIT) $(FAULT) $(FAULT_CLI) $(CONFIG):
	+@flock -x .pa2-build.lock $(MAKE) --no-print-directory PA2_BUILD_SERIALIZED=1 $@

endif
