/* Inject a SHA256 failure into the CLI for end-to-end error-path testing. */
#include <stddef.h>

unsigned char *__wrap_SHA256(const unsigned char *data, size_t length,
                              unsigned char *digest) {
    (void)data;
    (void)length;
    (void)digest;
    return NULL;
}
