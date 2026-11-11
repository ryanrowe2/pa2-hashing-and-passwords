CC = cc
CPPFLAGS = -Iinclude
CFLAGS = -std=c11 -O2 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes -Werror
LDFLAGS =
LDLIBS = -lcrypto
BIN = build/pwcrack
UNIT = build/test_core
SAN_FLAGS = -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer

ifeq ($(SANITIZE),1)
CFLAGS += $(SAN_FLAGS)
LDFLAGS += -fsanitize=address,undefined
endif

.PHONY: all clean test bench analyze
all: $(BIN)

build:
	mkdir -p build

$(BIN): src/main.c src/pwcrack.c include/pwcrack.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) src/main.c src/pwcrack.c $(LDFLAGS) $(LDLIBS) -o $@

$(UNIT): tests/test_core.c src/pwcrack.c include/pwcrack.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_core.c src/pwcrack.c $(LDFLAGS) $(LDLIBS) -o $@

test: $(BIN) $(UNIT)
	./$(UNIT)
	PWCRACK_BIN=./$(BIN) python3 -m unittest discover -s tests -p 'test_*.py' -v

bench: $(BIN)
	PWCRACK_BIN=./$(BIN) python3 tests/benchmark.py

analyze:
	clang --analyze -std=c11 -Wall -Wextra -Wpedantic -Iinclude src/main.c src/pwcrack.c

clean:
	rm -rf build
