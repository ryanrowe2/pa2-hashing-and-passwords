#include "pwcrack.h"

#include <stdio.h>
#include <signal.h>

/* Report buffered output failures, including errors during the final flush. */
static int finish_output(int write_ok) {
    if (!write_ok) {
        perror("Error: unable to write standard output");
        return 2;
    }
    if (fclose(stdout) == EOF) {
        perror("Error: unable to write standard output");
        return 2;
    }
    return 0;
}

/* Read a complete valid line. Reject the first invalid byte immediately,
   without waiting indefinitely for a newline or treating fragments as lines. */
enum read_status {
    READ_OK,
    READ_EOF,
    READ_TOO_LONG,
    READ_NUL,
    READ_ERROR
};

static enum read_status read_candidate(FILE *input,
                                        char candidate[PWCRACK_MAX_CANDIDATE_BYTES + 1u],
                                        size_t *length) {
    size_t count = 0;
    int ch;
    int seen = 0;

    while ((ch = fgetc(input)) != EOF) {
        seen = 1;
        if (ch == '\n') {
            break;
        }
        if (ch == 0) {
            return READ_NUL;
        }
        if (count == PWCRACK_MAX_CANDIDATE_BYTES) {
            return READ_TOO_LONG;
        }
        candidate[count++] = (char)ch;
    }
    if (ferror(input)) {
        return READ_ERROR;
    }
    if (!seen && ch == EOF) {
        return READ_EOF;
    }
    candidate[count] = '\0';
    *length = count;
    return READ_OK;
}

/* Display bytes without allowing terminal control-sequence interpretation.
   Non-ASCII bytes use \xHH escapes; backslashes are doubled for reversibility. */
static int print_escaped_candidate(const char *candidate, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        unsigned char byte = (unsigned char)candidate[i];
        if (byte == '\\') {
            if (fputs("\\\\", stdout) == EOF) {
                return 0;
            }
        } else if (byte < 0x20u || byte > 0x7eu) {
            if (printf("\\x%02X", (unsigned int)byte) < 0) {
                return 0;
            }
        } else if (fputc((int)byte, stdout) == EOF) {
            return 0;
        }
    }
    return 1;
}

int main(int argc, char **argv) {
#ifdef SIGPIPE
    /* Cover diagnostic writes during argument validation as well. */
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        perror("Error: unable to configure broken-pipe handling");
        return 2;
    }
#endif

    if (argc != 2) {
        fputs("Usage: pwcrack <64-character SHA-256 hex digest>\n", stderr);
        return 2;
    }

    unsigned char expected[SHA256_DIGEST_LENGTH];
    if (!parse_sha256_hex(argv[1], expected)) {
        fprintf(stderr, "Error: expected exactly 64 ASCII hexadecimal characters\n");
        return 2;
    }

    char candidate[PWCRACK_MAX_CANDIDATE_BYTES + 1u];
    size_t length = 0;
    size_t line_number = 0;
    for (;;) {
        enum read_status status = read_candidate(stdin, candidate, &length);
        if (status == READ_EOF) {
            break;
        }
        ++line_number;
        if (status == READ_TOO_LONG) {
            fprintf(stderr, "Error: candidate on line %zu exceeds %u bytes\n",
                    line_number, PWCRACK_MAX_CANDIDATE_BYTES);
            return 2;
        }
        if (status == READ_NUL) {
            fprintf(stderr, "Error: candidate on line %zu contains a NUL byte\n",
                    line_number);
            return 2;
        }
        if (status == READ_ERROR) {
            fprintf(stderr, "Error: unable to read standard input\n");
            return 2;
        }

        int match = find_sha256_candidate(candidate, length, expected);
        if (match == -1) {
            fprintf(stderr, "Error: SHA-256 calculation failed\n");
            return 2;
        }
        if (match == 1) {
            int write_ok = fputs("Found password: SHA256(", stdout) != EOF;
            if (write_ok) {
                write_ok = print_escaped_candidate(candidate, length);
            }
            if (write_ok) {
                write_ok = printf(") = %s\n", argv[1]) >= 0;
            }
            return finish_output(write_ok);
        }
    }

    return finish_output(puts("Did not find a matching password") != EOF);
}
