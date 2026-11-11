#include "pwcrack.h"

#include <stdio.h>
#include <string.h>

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "FAIL: %s at %s:%d\n", #expr, __FILE__, __LINE__); \
        return 1; \
    } \
} while (0)

static int test_hex_parser(void) {
    const char *lower = "a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd";
    const char *upper = "A2C3B02CB22AF83D6D1EAD1D4E18D916599BE7C2EF2F017169327DF1F7C844FD";
    unsigned char digest[SHA256_DIGEST_LENGTH];
    CHECK(parse_sha256_hex(lower, digest) == 1);
    CHECK(digest[0] == 0xa2 && digest[30] == 0x44 && digest[31] == 0xfd);
    CHECK(parse_sha256_hex(upper, digest) == 1);
    CHECK(digest[0] == 0xa2 && digest[31] == 0xfd);
    memset(digest, 0x5a, sizeof(digest));
    CHECK(parse_sha256_hex("", digest) == 0);
    CHECK(parse_sha256_hex("abc", digest) == 0);
    CHECK(parse_sha256_hex("a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844f", digest) == 0);
    CHECK(parse_sha256_hex("a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd0", digest) == 0);
    CHECK(parse_sha256_hex("g2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd", digest) == 0);
    CHECK(parse_sha256_hex("a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fg", digest) == 0);
    CHECK(parse_sha256_hex(NULL, digest) == 0);
    CHECK(parse_sha256_hex(lower, NULL) == 0);
    for (size_t i = 0; i < sizeof(digest); ++i) {
        CHECK(digest[i] == 0x5a);
    }
    return 0;
}

static int test_candidates(void) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    CHECK(SHA256((const unsigned char *)"seCret", 6u, digest) != NULL);

    char exact[] = "seCret";
    CHECK(find_sha256_candidate(exact, strlen(exact), digest) == 1);
    CHECK(strcmp(exact, "seCret") == 0);

    char one_flip[] = "secret";
    CHECK(find_sha256_candidate(one_flip, strlen(one_flip), digest) == 1);
    CHECK(strcmp(one_flip, "seCret") == 0);

    char multi_flip[] = "SECRET";
    CHECK(find_sha256_candidate(multi_flip, strlen(multi_flip), digest) == 0);
    CHECK(strcmp(multi_flip, "SECRET") == 0);

    char unrelated[] = "unrelated";
    CHECK(find_sha256_candidate(unrelated, strlen(unrelated), digest) == 0);
    CHECK(strcmp(unrelated, "unrelated") == 0);

    CHECK(find_sha256_candidate(NULL, 0u, digest) == -1);
    CHECK(find_sha256_candidate(exact, strlen(exact), NULL) == -1);

    char empty[] = "";
    CHECK(SHA256((const unsigned char *)"", 0u, digest) != NULL);
    CHECK(find_sha256_candidate(empty, 0u, digest) == 1);

    char boundary[PWCRACK_MAX_CANDIDATE_BYTES + 1u];
    memset(boundary, 'x', PWCRACK_MAX_CANDIDATE_BYTES);
    boundary[PWCRACK_MAX_CANDIDATE_BYTES - 1u] = 'A';
    boundary[PWCRACK_MAX_CANDIDATE_BYTES] = '\0';
    CHECK(SHA256((const unsigned char *)boundary, PWCRACK_MAX_CANDIDATE_BYTES, digest) != NULL);
    boundary[PWCRACK_MAX_CANDIDATE_BYTES - 1u] = 'a';
    CHECK(find_sha256_candidate(boundary, PWCRACK_MAX_CANDIDATE_BYTES, digest) == 1);
    CHECK(boundary[PWCRACK_MAX_CANDIDATE_BYTES - 1u] == 'A');

    /* UTF-8 bytes must never be interpreted as letters by the C locale. */
    char utf8[] = {(char)0xc3, (char)0xa9, 'A', '\0'};
    char target[] = {(char)0xc3, (char)0xa9, 'a', '\0'};
    CHECK(SHA256((const unsigned char *)target, 3u, digest) != NULL);
    CHECK(find_sha256_candidate(utf8, 3u, digest) == 1);
    CHECK(memcmp(utf8, target, sizeof(target)) == 0);

    char digits[] = "1234!";
    CHECK(SHA256((const unsigned char *)"notthis", 7u, digest) != NULL);
    CHECK(find_sha256_candidate(digits, strlen(digits), digest) == 0);
    CHECK(strcmp(digits, "1234!") == 0);
    return 0;
}

int main(void) {
    if (test_hex_parser() != 0 || test_candidates() != 0) {
        return 1;
    }
    puts("C unit tests passed");
    return 0;
}
