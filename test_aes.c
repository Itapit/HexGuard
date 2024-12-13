#include <stdio.h>
#include <string.h>
#include "aes.h"

#define AES_BLOCK_SIZE 16  // Block size in bytes
#define AES_KEY_SIZE_128 16 // Key size in bytes for AES-128
#define AES_KEY_SIZE_192 24 // Key size in bytes for AES-192
#define AES_KEY_SIZE_256 32 // Key size in bytes for AES-256

typedef uint8_t state_t[4][4];
typedef uint8_t key_128[16];
typedef uint8_t key_192[24];
typedef uint8_t key_256[32];

typedef int bool;
#define true 1
#define false 0

#define ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            printf("\033[0;31m"); \
            printf("Test failed: %s\n", message); \
            printf("\033[0m"); \
            return false; \
        } \
    } while (0)

#define RUN_TEST(test) \
    do { \
        printf("\033[0;34m"); \
        printf("Running %s...\n", #test); \
        printf("\033[0m"); \
        if (test()) { \
            printf("\033[0;32m"); \
            printf("%s passed.\n", #test); \
            printf("\033[0m"); \
        } else { \
            printf("\033[0;31m"); \
            printf("%s failed.\n", #test); \
            printf("\033[0m"); \
        } \
    } while (0)

    int test_create_key()
    {
        key_128 key_test_128 = {0}, key2 = {0}, key3 = {0};
        key_192 key_test_192 = {0};
        key_256 key_test_256 = {0};

        key_256 key_test_empty = {0};

        create_key(key_test_128, 128);
        create_key(key_test_192, 192);
        create_key(key_test_256, 256);

        create_key(key2, 128);
        create_key(key3, 128);

        // printf("key_test_128:\n");
        // for (int i = 0; i < AES_KEY_SIZE_128; i++)
        // {
        //     printf("%02X", key_test_128[i]);
        // }
        // printf("\n");

        // printf("key_test_192:\n");
        // for (int i = 0; i < AES_KEY_SIZE_192; i++)
        // {
        //     printf("%02X", key_test_192[i]);
        // }
        // printf("\n");

        // printf("key_test_256:\n");
        // for (int i = 0; i < AES_KEY_SIZE_256; i++)
        // {
        //     printf("%02X", key_test_256[i]);
        // }
        // printf("\n");

        // check if the keys are empty
        ASSERT(memcmp(key_test_128, key_test_empty, AES_KEY_SIZE_128) == 1, "Key 128 is all zeros");
        ASSERT(memcmp(key_test_192, key_test_empty, AES_KEY_SIZE_192) == 1, "Key 192 is all zeros");
        ASSERT(memcmp(key_test_256, key_test_empty, AES_KEY_SIZE_256) == 1, "Key 256 is all zeros");
        // check if the keys are identical

        ASSERT(memcmp(key_test_128, key2, AES_KEY_SIZE_128) != 0, "Key1 and Key2 are identical");
        ASSERT(memcmp(key2, key3, AES_KEY_SIZE_128) != 0, "Key2 and Key3 are identical");
        ASSERT(memcmp(key_test_128, key3, AES_KEY_SIZE_128) != 0, "Key1 and Key3 are identical");
        return true;
    }
int test_stringToState()
{
    //input string
    char input[] = "abcdefghijklmnop";
    //state after function
    state_t state;

    state_t expected_state = {
        {0x61, 0x62, 0x63, 0x64}, // 'a', 'b', 'c', 'd'
        {0x65, 0x66, 0x67, 0x68}, // 'e', 'f', 'g', 'h'
        {0x69, 0x6a, 0x6b, 0x6c}, // 'i', 'j', 'k', 'l'
        {0x6d, 0x6e, 0x6f, 0x70}  // 'm', 'n', 'o', 'p'
    };
    
    stringToState(input, state);

    // printf("Actual state:\n");
    // for (int i = 0; i < 4; i++) {
    //     for (int j = 0; j < 4; j++) {
    //         printf("%c ", state[i][j]);
    //     }
    //     printf("\n");
    // }

    // // Print expected state
    // printf("Expected state:\n");
    // for (int i = 0; i < 4; i++) {
    //     for (int j = 0; j < 4; j++) {
    //         printf("%c ", expected_state[i][j]);
    //     }
    //     printf("\n");
    // }

    // printf("%d\n", memcmp(state, expected_state, 16));
    ASSERT(memcmp(state, expected_state, 16) == 0, "stringToState failed.");

    return true;
}
int test_stateToString()
{
    state_t state = {
        {0x61, 0x62, 0x63, 0x64}, // 'a', 'b', 'c', 'd'
        {0x65, 0x66, 0x67, 0x68}, // 'e', 'f', 'g', 'h'
        {0x69, 0x6a, 0x6b, 0x6c}, // 'i', 'j', 'k', 'l'
        {0x6d, 0x6e, 0x6f, 0x70}  // 'm', 'n', 'o', 'p'
    };
    char given_str[AES_BLOCK_SIZE + 1] = {0};
    char expected_output[] = "abcdefghijklmnop";
    
    stateToString(state, given_str);

    // printf("Actual string:\n");
    // for (int i = 0; i < 16; i++)
    // {
    //     printf("%c", given_str[i]);
    // }printf("\n");
    // printf("Expected string:\n");
    // printf("%s\n", expected_output);

    ASSERT(memcmp(given_str, expected_output, AES_BLOCK_SIZE) == 0, "stateToString failed.");
    return true;
}
int test_AddRoundKey() {
    // Input state
    state_t state = {
        {0x00, 0x11, 0x22, 0x33},
        {0x44, 0x55, 0x66, 0x77},
        {0x88, 0x99, 0xAA, 0xBB},
        {0xCC, 0xDD, 0xEE, 0xFF}
    };

    // Round key
    uint8_t round_key[16] = {
        0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01
    };

    // Expected result
    state_t expected_state = {
        {0x01, 0x10, 0x23, 0x32},
        {0x45, 0x54, 0x67, 0x76},
        {0x89, 0x98, 0xAB, 0xBA},
        {0xCD, 0xDC, 0xEF, 0xFE}
    };

    // Call AddRoundKey
    AddRoundKey(state, round_key);

    // Check results
    ASSERT(memcmp(state, expected_state, sizeof(state)) == 0, "AddRoundKey failed.");
    return true;
}

int main() {
    printf("\033[0;35m");
    printf("Starting AES tests...\n");
    printf("\033[0m");

    // Run tests
    RUN_TEST(test_stringToState);
    RUN_TEST(test_stateToString);
    RUN_TEST(test_create_key);
    RUN_TEST(test_AddRoundKey);

    printf("\033[0;35m");
    printf("All tests completed.\n");
    printf("\033[0m");
    return 0;
}