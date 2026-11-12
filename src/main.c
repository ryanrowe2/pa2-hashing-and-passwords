#include "pwcrack.h"

#include <stdio.h>

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

/* The reader consumes one complete line, including when it is invalid.
   It never treats fragments of an oversized line as separate candidates. */
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
    int too_long = 0;
    int contains_nul = 0;

    while ((ch = fgetc(input)) != EOF) {
        seen = 1;
        if (ch == '\n') {
            break;
        }
        if (ch == 0) {
            contains_nul = 1;
        }
        if (count < PWCRACK_MAX_CANDIDATE_BYTES) {
            candidate[count++] = (char)ch;
        } else {
            too_long = 1;
        }
    }
    if (ferror(input)) {
        return READ_ERROR;
    }
    if (!seen && ch == EOF) {
        return READ_EOF;
    }
    if (too_long) {
        return READ_TOO_LONG;
    }
    if (contains_nul) {
        return READ_NUL;
    }
    candidate[count] = '\0';
    *length = count;
    return READ_OK;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <64-character SHA-256 hex digest>\n", argv[0]);
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
            return finish_output(printf("Found password: SHA256(%s) = %s\n",
                                        candidate, argv[1]) >= 0);
        }
    }

    return finish_output(puts("Did not find a matching password") != EOF);
}
