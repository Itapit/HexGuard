#include <stdio.h>
#include <string.h>
#include "aes.h"

typedef uint8_t state_t[4][4];

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
    char given_str[16];
    char expected_output[] = "abcdefghijklmnop";
    
    stateToString(state, given_str);

    // printf("Actual string:\n");
    // for (int i = 0; i < 16; i++)
    // {
    //     printf("%c", given_str[i]);
    // }printf("\n");
    // printf("Expected string:\n");
    // printf("%s\n", expected_output);

    ASSERT(memcmp(given_str, expected_output, sizeof(given_str)) == 0, "stateToString failed.");
    return true;
}
// int test_AddRoundKey() {
//     // Input state
//     state_t state = {
//         {0x00, 0x11, 0x22, 0x33},
//         {0x44, 0x55, 0x66, 0x77},
//         {0x88, 0x99, 0xAA, 0xBB},
//         {0xCC, 0xDD, 0xEE, 0xFF}
//     };

//     // Round key
//     uint8_t round_key[16] = {
//         0x01, 0x01, 0x01, 0x01,
//         0x01, 0x01, 0x01, 0x01,
//         0x01, 0x01, 0x01, 0x01,
//         0x01, 0x01, 0x01, 0x01
//     };

//     // Expected result
//     state_t expected_state = {
//         {0x01, 0x10, 0x23, 0x32},
//         {0x45, 0x54, 0x67, 0x76},
//         {0x89, 0x98, 0xAB, 0xBA},
//         {0xCD, 0xDC, 0xEF, 0xFE}
//     };

//     // Call AddRoundKey
//     AddRoundKey(state, round_key);

//     // Check results
//     ASSERT(memcmp(state, expected_state, sizeof(state)) == 0, "AddRoundKey failed.");
//     return false;
// }


int main() {
    printf("Starting AES tests...\n");

    // Run tests
    RUN_TEST(test_stringToState);
    RUN_TEST(test_stateToString);

    printf("All tests completed.\n");
    return 0;
}
