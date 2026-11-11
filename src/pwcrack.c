#include "pwcrack.h"

#include <openssl/crypto.h>
#include <string.h>

static int hex_nibble(unsigned char ch) {
    if (ch >= '0' && ch <= '9') {
        return (int)(ch - '0');
    }
    if (ch >= 'a' && ch <= 'f') {
        return (int)(ch - 'a') + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return (int)(ch - 'A') + 10;
    }
    return -1;
}

int parse_sha256_hex(const char *hex, unsigned char digest[SHA256_DIGEST_LENGTH]) {
    if (hex == NULL || digest == NULL || strlen(hex) != SHA256_DIGEST_LENGTH * 2u) {
        return 0;
    }

    /* Validate before modifying digest so malformed input cannot leave a
       partially parsed value in the caller's output buffer. */
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH * 2u; ++i) {
        if (hex_nibble((unsigned char)hex[i]) < 0) {
            return 0;
        }
    }
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        int high = hex_nibble((unsigned char)hex[2u * i]);
        int low = hex_nibble((unsigned char)hex[2u * i + 1u]);
        digest[i] = (unsigned char)((high << 4) | low);
    }
    return 1;
}

static int matches_digest(const char *candidate, size_t length,
                          const unsigned char digest[SHA256_DIGEST_LENGTH]) {
    unsigned char computed[SHA256_DIGEST_LENGTH];
    if (SHA256((const unsigned char *)candidate, length, computed) == NULL) {
        return -1;
    }
    return CRYPTO_memcmp(computed, digest, SHA256_DIGEST_LENGTH) == 0 ? 1 : 0;
}

int find_sha256_candidate(char *candidate, size_t length,
                          const unsigned char digest[SHA256_DIGEST_LENGTH]) {
    if (candidate == NULL || digest == NULL) {
        return -1;
    }

    int result = matches_digest(candidate, length, digest);
    if (result != 0) {
        return result;
    }

    for (size_t i = 0; i < length; ++i) {
        unsigned char original = (unsigned char)candidate[i];
        unsigned char flipped;
        if (original >= 'a' && original <= 'z') {
            flipped = (unsigned char)(original - 'a' + 'A');
        } else if (original >= 'A' && original <= 'Z') {
            flipped = (unsigned char)(original - 'A' + 'a');
        } else {
            continue;
        }

        candidate[i] = (char)flipped;
        result = matches_digest(candidate, length, digest);
        if (result == 1) {
            return 1;
        }
        candidate[i] = (char)original;
        if (result == -1) {
            return -1;
        }
    }
    return 0;
}
