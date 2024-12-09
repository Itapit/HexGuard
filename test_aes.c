#include <stdio.h>
#include <string.h>
#include "aes.h"

typedef int bool;
#define true 1
#define false 0

#define ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            printf("Test failed: %s\n", message); \
            return false; \
        } \
    } while (0)

#define RUN_TEST(test) \
    do { \
        printf("Running %s...\n", #test); \
        if (test()) { \
            printf("%s passed.\n", #test); \
        } else { \
            printf("%s failed.\n", #test); \
        } \
    } while (0)


int test_AddRoundKey() {
    // Input state
    uint8_t state[4][4] = {
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
    uint8_t expected[4][4] = {
        {0x01, 0x10, 0x23, 0x32},
        {0x45, 0x54, 0x67, 0x76},
        {0x89, 0x98, 0xAB, 0xBA},
        {0xCD, 0xDC, 0xEF, 0xFE}
    };

    // Call AddRoundKey
    AddRoundKey(state, round_key);

    // Check results
    ASSERT(memcmp(state, expected, sizeof(state)) == 0, "AddRoundKey failed.");
    return true;
}


int main() {
    printf("Starting AES tests...\n");

    // Run tests
    RUN_TEST(test_AddRoundKey);
    // Add more tests as needed

    printf("All tests completed.\n");
    return 0;
}
