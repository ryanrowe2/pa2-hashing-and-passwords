// pwcrack.c

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/sha.h>
#include <ctype.h>

// Function prototypes
uint8_t hex_to_byte(unsigned char h1, unsigned char h2);
void hexstr_to_hash(char hexstr[], unsigned char hash[32]);
int8_t check_password(char password[], unsigned char given_hash[32]);
int8_t crack_password(char password[], unsigned char given_hash[32]);

// Uncomment the following to run tests

void test_hex_to_byte();
void test_hexstr_to_hash();
void test_check_password();
void test_crack_password();


int main(int argc, char **argv) {
    // Uncomment for testing

    const int testing = 0;
    if (testing) {
        test_hex_to_byte();
        test_hexstr_to_hash();
        test_check_password();
        test_crack_password();
        printf("All tests passed!\n");
        return 0;
    }
   

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <SHA256 hash in hex>\n", argv[0]);
        return 1;
    }

    // Milestone 1: Convert the input hash string to byte array
    unsigned char given_hash[32];
    hexstr_to_hash(argv[1], given_hash);

    // Read potential passwords from stdin
    char password[1024]; // Assuming maximum password length of 1023
    int found = 0;

    while (fgets(password, sizeof(password), stdin) != NULL) {
        // Remove trailing newline character
        size_t len = strlen(password);
        if (len > 0 && password[len - 1] == '\n') {
            password[len - 1] = '\0';
            len--;
        }

        // Make a copy of the password for manipulation
        char original_password[1024];
        strncpy(original_password, password, sizeof(original_password));

        // First, check the original password
        if (check_password(password, given_hash)) {
            printf("Found password: SHA256(%s) = %s\n", password, argv[1]);
            found = 1;
            break;
        }

        // Now, try variations with single character case change
        if (crack_password(password, given_hash)) {
            printf("Found password: SHA256(%s) = %s\n", password, argv[1]);
            found = 1;
            break;
        }

        // Restore the original password before the next iteration
        strncpy(password, original_password, sizeof(password));
    }

    if (!found) {
        printf("Did not find a matching password\n");
    }

    return 0;
}

// Function implementations

uint8_t hex_to_byte(unsigned char h1, unsigned char h2) {
    uint8_t byte = 0;

    if (h1 >= '0' && h1 <= '9') {
        byte += (h1 - '0') << 4;
    } else if (h1 >= 'a' && h1 <= 'f') {
        byte += (h1 - 'a' + 10) << 4;
    } else if (h1 >= 'A' && h1 <= 'F') {
        byte += (h1 - 'A' + 10) << 4;
    }

    if (h2 >= '0' && h2 <= '9') {
        byte += (h2 - '0');
    } else if (h2 >= 'a' && h2 <= 'f') {
        byte += (h2 - 'a' + 10);
    } else if (h2 >= 'A' && h2 <= 'F') {
        byte += (h2 - 'A' + 10);
    }

    return byte;
}

void hexstr_to_hash(char hexstr[], unsigned char hash[32]) {
    for (int i = 0; i < 32; i++) {
        hash[i] = hex_to_byte(hexstr[2 * i], hexstr[2 * i + 1]);
    }
}

int8_t check_password(char password[], unsigned char given_hash[32]) {
    unsigned char computed_hash[32];
    SHA256((unsigned char *)password, strlen(password), computed_hash);

    if (memcmp(computed_hash, given_hash, 32) == 0) {
        return 1;
    } else {
        return 0;
    }
}

int8_t crack_password(char password[], unsigned char given_hash[32]) {
    size_t len = strlen(password);
    for (size_t i = 0; i < len; i++) {
        if (isalpha((unsigned char)password[i])) {
            char original_char = password[i];

            // Change case
            if (islower((unsigned char)password[i])) {
                password[i] = toupper((unsigned char)password[i]);
            } else if (isupper((unsigned char)password[i])) {
                password[i] = tolower((unsigned char)password[i]);
            }

            // Check the password
            if (check_password(password, given_hash)) {
                return 1;
            }

            // Restore original character before moving to next character
            password[i] = original_char;
        }
    }

    return 0;
}

// Test functions

void test_hex_to_byte() {
    assert(hex_to_byte('c', '8') == 200);
    assert(hex_to_byte('0', '3') == 3);
    assert(hex_to_byte('0', 'a') == 10);
    assert(hex_to_byte('1', '0') == 16);
}

void test_hexstr_to_hash() {
    char hexstr[64] = "a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd";
    unsigned char hash[32];
    hexstr_to_hash(hexstr, hash);
    assert(hash[0] == 0xa2);
    assert(hash[31] == 0xfd);
    assert(hash[30] == 0x44);
} 

void test_check_password() {
    char hash_as_hexstr[] = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"; // SHA256 of "password"
    unsigned char given_hash[32];
    hexstr_to_hash(hash_as_hexstr, given_hash);
    assert(check_password("password", given_hash) == 1);
    assert(check_password("wrongpass", given_hash) == 0);
}

void test_crack_password() {
    char hash_as_hexstr[] = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"; // SHA256 of "password"
    unsigned char given_hash[32];
    hexstr_to_hash(hash_as_hexstr, given_hash);
    char password[] = "paSsword";
    int8_t match = crack_password(password, given_hash);
    assert(match == 1);
    assert(strcmp(password, "password") == 0); // 'S' has been changed to 's'
}


