#ifndef PWCRACK_H
#define PWCRACK_H

#include <stddef.h>
#include <openssl/sha.h>

/* Preserve the assignment's bounded, line-oriented input model. */
#define PWCRACK_MAX_CANDIDATE_BYTES 1023u

/* Return 1 only for exactly 64 valid ASCII hexadecimal characters.
   The output digest is left unchanged if validation fails. */
int parse_sha256_hex(const char *hex, unsigned char digest[SHA256_DIGEST_LENGTH]);

/* Check the candidate and each possible single ASCII letter case flip.
   Return 1 on a match, 0 for no match, or -1 for invalid arguments,
   lengths above PWCRACK_MAX_CANDIDATE_BYTES, or a hashing error.
   On success, the candidate contains the matching variation; on failure,
   it remains unchanged. Length counts bytes, excluding the terminating NUL. */
int find_sha256_candidate(char *candidate, size_t length,
                          const unsigned char digest[SHA256_DIGEST_LENGTH]);

#endif
