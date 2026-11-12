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

$(BIN): src/main.c src/pwcrack.c include/pwcrack.h Makefile $(CONFIG) | build
	$(CC) $(CPPFLAGS) $(CFLAGS) src/main.c src/pwcrack.c $(LDFLAGS) $(LDLIBS) -o $@

$(UNIT): tests/test_core.c src/pwcrack.c include/pwcrack.h Makefile $(CONFIG) | build
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_core.c src/pwcrack.c $(LDFLAGS) $(LDLIBS) -o $@

$(FAULT): tests/test_fault.c src/pwcrack.c include/pwcrack.h Makefile $(CONFIG) | build
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_fault.c src/pwcrack.c $(LDFLAGS) -Wl,--wrap=SHA256 $(LDLIBS) -o $@

$(FAULT_CLI): tests/sha256_fail.c src/main.c src/pwcrack.c include/pwcrack.h Makefile $(CONFIG) | build
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/sha256_fail.c src/main.c src/pwcrack.c $(LDFLAGS) -Wl,--wrap=SHA256 $(LDLIBS) -o $@

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
