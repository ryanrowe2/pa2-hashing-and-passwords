/* Deterministic injection of OpenSSL SHA256 failures using GNU ld --wrap. */
#include "pwcrack.h"

#include <stdio.h>
#include <string.h>

static int fail_on_call;
static int calls;

unsigned char *__real_SHA256(const unsigned char *data, size_t length,
                              unsigned char *digest);

unsigned char *__wrap_SHA256(const unsigned char *data, size_t length,
                              unsigned char *digest) {
    ++calls;
    if (fail_on_call == calls) {
        return NULL;
    }
    return __real_SHA256(data, length, digest);
}

int main(void) {
    unsigned char digest[SHA256_DIGEST_LENGTH] = {0};
    char candidate[] = "aBc123";

    fail_on_call = 1;
    calls = 0;
    if (find_sha256_candidate(candidate, strlen(candidate), digest) != -1 ||
        strcmp(candidate, "aBc123") != 0 || calls != 1) {
        fputs("FAIL: initial SHA256 error handling\n", stderr);
        return 1;
    }

    fail_on_call = 2;
    calls = 0;
    if (find_sha256_candidate(candidate, strlen(candidate), digest) != -1 ||
        strcmp(candidate, "aBc123") != 0 || calls != 2) {
        fputs("FAIL: SHA256 error handling during case variations\n", stderr);
        return 1;
    }

    puts("Injected SHA256 failure tests passed");
    return 0;
}
