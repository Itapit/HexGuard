#pragma region ---------- PreProcessor, typedef and macros ----------
#include <stdio.h>
#include <string.h>
#include "aes.h"

#define BLOCK_SIZE_BYTES 16  // Block size in bytes
#define KEY_SIZE_BYTES_128 16 // Key size in bytes for AES-128
#define KEY_SIZE_BYTES_192 24 // Key size in bytes for AES-192
#define KEY_SIZE_BYTES_256 32 // Key size in bytes for AES-256

#define KEY_SIZE_BITS_128 128 // Key size in bits for AES-128
#define KEY_SIZE_BITS_192 192 // Key size in bits for AES-192
#define KEY_SIZE_BITS_256 256 // Key size in bits for AES-256

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
#pragma endregion
#pragma region ---------- Public Functions (DLL Main Functions) ----------
bool test_create_key() {
    key_128 key_test_128 = {0}, key2 = {0}, key3 = {0};
    key_192 key_test_192 = {0};
    key_256 key_test_256 = {0};
    key_256 key_test_empty = {0};

    create_key(key_test_128, KEY_SIZE_BITS_128);
    create_key(key_test_192, KEY_SIZE_BITS_192);
    create_key(key_test_256, KEY_SIZE_BITS_256);
    create_key(key2, KEY_SIZE_BITS_128);
    create_key(key3, KEY_SIZE_BITS_128);

    // printf("key_test_128:\n");
    // for (int i = 0; i < KEY_SIZE_BYTES_128; i++)
    // {
    //     printf("%02X", key_test_128[i]);
    // }
    // printf("\n");
    // printf("key_test_192:\n");
    // for (int i = 0; i < KEY_SIZE_BYTES_192; i++)
    // {
    //     printf("%02X", key_test_192[i]);
    // }
    // printf("\n");
    // printf("key_test_256:\n");
    // for (int i = 0; i < KEY_SIZE_BYTES_256; i++)
    // {
    //     printf("%02X", key_test_256[i]);
    // }
    // printf("\n");

    // check if the keys are empty
    ASSERT(memcmp(key_test_128, key_test_empty, KEY_SIZE_BYTES_128) == 1, "Key 128 is all zeros");
    ASSERT(memcmp(key_test_192, key_test_empty, KEY_SIZE_BYTES_192) == 1, "Key 192 is all zeros");
    ASSERT(memcmp(key_test_256, key_test_empty, KEY_SIZE_BYTES_256) == 1, "Key 256 is all zeros");

    // check if the keys are identical
    ASSERT(memcmp(key_test_128, key2, KEY_SIZE_BYTES_128) != 0, "Key1 and Key2 are identical");
    ASSERT(memcmp(key2, key3, KEY_SIZE_BYTES_128) != 0, "Key2 and Key3 are identical");
    ASSERT(memcmp(key_test_128, key3, KEY_SIZE_BYTES_128) != 0, "Key1 and Key3 are identical");

    return true;
}
bool test_encrypt_text_ECB() {
    const char *input_text = "Hello, AES ECB!";
    const char *key_hex = "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c";

    key_128 key;
    hex_line_to_key(key_hex, key, KEY_SIZE_BYTES_128);  // Convert key from hex

    const uint8_t expected_output[] = {
        0x33, 0xa1, 0xfc, 0xcb, 0xd7, 0x20, 0x1b, 0xe1,
        0x8c, 0x63, 0xf9, 0x2b, 0x7c, 0xf7, 0x57, 0xcc
    };

    char output_text[BLOCK_SIZE_BYTES * 2] = {0};  // Output buffer for encrypted text

    // Call encrypt_text for ECB mode
    encrypt_text("ECB", input_text, output_text, key, KEY_SIZE_BITS_128, NULL);

    // printf("Actual Encrypted Output (Hex): ");
    // for (size_t i = 0; i < BLOCK_SIZE_BYTES; i++) {
    //     printf("%02x ", (uint8_t)output_text[i]);
    // }
    // printf("\n");

    // Verify the encrypted output matches the expected result
    ASSERT(memcmp(output_text, expected_output, BLOCK_SIZE_BYTES) == 0, "encrypt_text ECB failed.");

    return true;
}

#pragma endregion
#pragma region ---------- Internal AES Core Functions ----------
// ------------- Internal AES Core Functions -------------
bool test_Cipher() {
    const char *state_hex ="32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34";
    state_t state;
    hex_line_to_state(state_hex, state);
    //print_state(state);

    const char *key_hex = "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c";
    key_128 key; 

    hex_line_to_key(key_hex, key, 16);
    state_t expected_state = {
        {0x39, 0x02, 0xdc, 0x19}, 
        {0x25, 0xdc, 0x11, 0x6a}, 
        {0x84, 0x09, 0x85, 0x0b}, 
        {0x1d, 0xfb, 0x97, 0x32}
    };

    Cipher(state, key, KEY_SIZE_BITS_128);

    // print_state(state);
    ASSERT(memcmp(state, expected_state, sizeof(state_t)) == 0, "Cipher failed.");
    return true;
}
bool test_AddRoundKey() {
    // Input state
    state_t state = {
        {0x32, 0x88, 0x31, 0xe0}, 
        {0x43, 0x5a, 0x31, 0x37}, 
        {0xf6, 0x30, 0x98, 0x07}, 
        {0xa8, 0x8d, 0xa2, 0x34}
    };

    // Round key
    uint8_t round_key[16] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };

    // Expected result
    state_t expected_state = {
        {0x19, 0xa0, 0x9a, 0xe9}, 
        {0x3d, 0xf4, 0xc6, 0xf8}, 
        {0xe3, 0xe2, 0x8d, 0x48}, 
        {0xbe, 0x2b, 0x2a, 0x08}
    };

    // Call AddRoundKey
    AddRoundKey(state, round_key);

    // Check results
    ASSERT(memcmp(state, expected_state, sizeof(state)) == 0, "AddRoundKey failed.");
    return true;
}
bool test_SubBytes() {
    state_t state = {
    {0x19, 0xa0, 0x9a, 0xe9},
    {0x3d, 0xf4, 0xc6, 0xf8},
    {0xe3, 0xe2, 0x8d, 0x48},
    {0xbe, 0x2b, 0x2a, 0x08}
    };

    state_t expected_state = {
    {0xd4, 0xe0, 0xb8, 0x1e},
    {0x27, 0xbf, 0xb4, 0x41},
    {0x11, 0x98, 0x5d, 0x52},
    {0xae, 0xf1, 0xe5, 0x30}
    };

    SubBytes(state);

    ASSERT(memcmp(state, expected_state, sizeof(state_t)) == 0, "SubBytes failed.");
    return true;
}
bool test_ShiftRows() {
    state_t state = {
    {0x00, 0x01, 0x02, 0x03},
    {0x10, 0x11, 0x12, 0x13},
    {0x20, 0x21, 0x22, 0x23},
    {0x30, 0x31, 0x32, 0x33}
    };

    state_t expected = {
    {0x00, 0x01, 0x02, 0x03},
    {0x11, 0x12, 0x13, 0x10},
    {0x22, 0x23, 0x20, 0x21},
    {0x33, 0x30, 0x31, 0x32}
    };

    ShiftRows(state);

    ASSERT(memcmp(state, expected, sizeof(state_t)) == 0, "ShiftRows failed.");
    return true;
}
bool test_MixColumns() {
    state_t state = {
        {0xd4, 0xe0, 0xb8, 0x1e}, 
        {0xbf, 0xb4, 0x41, 0x27}, 
        {0x5d, 0x52, 0x11, 0x98}, 
        {0x30, 0xae, 0xf1, 0xe5}
    };

    state_t expected_state = {
        {0x04, 0xe0, 0x48, 0x28}, 
        {0x66, 0xcb, 0xf8, 0x06}, 
        {0x81, 0x19, 0xd3, 0x26}, 
        {0xe5, 0x9a, 0x7a, 0x4c}
    };
    MixColumns(state);
    //print_state(state);
    ASSERT(memcmp(state, expected_state, sizeof(state_t)) == 0, "MixColumns failed.");
    return true;
}
bool test_KeyExpansion_128() {
    const char *hex_line = "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c";
    uint8_t key[16];  // For AES-128 key size (16 bytes)

    hex_line_to_key(hex_line, key, 16);
    // print_key(key, 16);

     uint8_t expected_round_keys[176] = {  //appendix key expansion
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, // Round 0
        0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c, 0x76, 0x05, // Round 1
        0xf2, 0xc2, 0x95, 0xf2, 0x7a, 0x96, 0xb9, 0x43, 0x59, 0x35, 0x80, 0x7a, 0x73, 0x59, 0xf6, 0x7f, // Round 2
        0x3d, 0x80, 0x47, 0x7d, 0x47, 0x16, 0xfe, 0x3e, 0x1e, 0x23, 0x7e, 0x44, 0x6d, 0x7a, 0x88, 0x3b, // Round 3
        0xef, 0x44, 0xa5, 0x41, 0xa8, 0x52, 0x5b, 0x7f, 0xb6, 0x71, 0x25, 0x3b, 0xdb, 0x0b, 0xad, 0x00, // Round 4
        0xd4, 0xd1, 0xc6, 0xf8, 0x7c, 0x83, 0x9d, 0x87, 0xca, 0xf2, 0xb8, 0xbc, 0x11, 0xf9, 0x15, 0xbc, // Round 5
        0x6d, 0x88, 0xa3, 0x7a, 0x11, 0x0b, 0x3e, 0xfd, 0xdb, 0xf9, 0x86, 0x41, 0xca, 0x00, 0x93, 0xfd, // Round 6
        0x4e, 0x54, 0xf7, 0x0e, 0x5f, 0x5f, 0xc9, 0xf3, 0x84, 0xa6, 0x4f, 0xb2, 0x4e, 0xa6, 0xdc, 0x4f, // Round 7
        0xea, 0xd2, 0x73, 0x21, 0xb5, 0x8d, 0xba, 0xd2, 0x31, 0x2b, 0xf5, 0x60, 0x7f, 0x8d, 0x29, 0x2f, // Round 8
        0xac, 0x77, 0x66, 0xf3, 0x19, 0xfa, 0xdc, 0x21, 0x28, 0xd1, 0x29, 0x41, 0x57, 0x5c, 0x00, 0x6e, // Round 9
        0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63, 0x0c, 0xa6  // Round 10
    };

    uint8_t round_keys[176];
    KeyExpansion(key, round_keys, KEY_SIZE_BITS_128);

    // printf("Generated Round Keys:\n");
    // print_round_keys(round_keys, 10);

    ASSERT(memcmp(round_keys, expected_round_keys, sizeof(expected_round_keys)) == 0, "KeyExpansion for AES-128 failed.");
    return true;
}
bool test_KeyExpansion_192() {
    uint8_t key[24] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b,
        0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };
    uint8_t expected_round_keys[208] = {
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 
    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b, 0xfe, 0x0c, 0x91, 0xf7, 0x24, 0x02, 0xf5, 0xa5,
    0xec, 0x12, 0x06, 0x8e, 0x6c, 0x82, 0x7f, 0x6b, 0x0e, 0x7a, 0x95, 0xb9, 0x5c, 0x56, 0xfe, 0xc2,
    0x4d, 0xb7, 0xb4, 0xbd, 0x69, 0xb5, 0x41, 0x18, 0x85, 0xa7, 0x47, 0x96, 0xe9, 0x25, 0x38, 0xfd,
    0xe7, 0x5f, 0xad, 0x44, 0xbb, 0x09, 0x53, 0x86, 0x48, 0x5a, 0xf0, 0x57, 0x21, 0xef, 0xb1, 0x4f,
    0xa4, 0x48, 0xf6, 0xd9, 0x4d, 0x6d, 0xce, 0x24, 0xaa, 0x32, 0x63, 0x60, 0x11, 0x3b, 0x30, 0xe6,
    0xa2, 0x5e, 0x7e, 0xd5, 0x83, 0xb1, 0xcf, 0x9a, 0x27, 0xf9, 0x39, 0x43, 0x6a, 0x94, 0xf7, 0x67,
    0xc0, 0xa6, 0x94, 0x07, 0xd1, 0x9d, 0xa4, 0xe1, 0xec, 0x17, 0x86, 0xeb, 0x6f, 0xa6, 0x49, 0x71,
    0x48, 0x5f, 0x70, 0x32, 0x22, 0xcb, 0x87, 0x55, 0xe2, 0x6d, 0x13, 0x52, 0x33, 0xf0, 0xb7, 0xb3, 
    0x40, 0xbe, 0xeb, 0x28, 0x2f, 0x18, 0xa2, 0x59, 0x67, 0x47, 0xd2, 0x6b, 0x45, 0x8c, 0x55, 0x3e,
    0xa7, 0xe1, 0x46, 0x6c, 0x94, 0x11, 0xf1, 0xdf, 0x82, 0x1f, 0x75, 0x0a, 0xad, 0x07, 0xd7, 0x53,
    0xca, 0x40, 0x05, 0x38, 0x8f, 0xcc, 0x50, 0x06, 0x28, 0x2d, 0x16, 0x6a, 0xbc, 0x3c, 0xe7, 0xb5,
    0xe9, 0x8b, 0xa0, 0x6f, 0x44, 0x8c, 0x77, 0x3c, 0x8e, 0xcc, 0x72, 0x04, 0x01, 0x00, 0x22, 0x02
    };

    uint8_t round_keys[208];
    KeyExpansion(key, round_keys, KEY_SIZE_BITS_192);

    // printf("Generated Round Keys:\n");
    // print_round_keys(round_keys, 12);
    ASSERT(memcmp(round_keys, expected_round_keys, sizeof(expected_round_keys)) == 0, "KeyExpansion for AES-192 failed.");
    return true;
}
bool test_keyExpansion_256() {
    uint8_t key[32]= {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };
    uint8_t expected_round_keys[240] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
        0x9b, 0xa3, 0x54, 0x11, 0x8e, 0x69, 0x25, 0xaf, 0xa5, 0x1a, 0x8b, 0x5f, 0x20, 0x67, 0xfc, 0xde,
        0xa8, 0xb0, 0x9c, 0x1a, 0x93, 0xd1, 0x94, 0xcd, 0xbe, 0x49, 0x84, 0x6e, 0xb7, 0x5d, 0x5b, 0x9a,
        0xd5, 0x9a, 0xec, 0xb8, 0x5b, 0xf3, 0xc9, 0x17, 0xfe, 0xe9, 0x42, 0x48, 0xde, 0x8e, 0xbe, 0x96, 
        0xb5, 0xa9, 0x32, 0x8a, 0x26, 0x78, 0xa6, 0x47, 0x98, 0x31, 0x22, 0x29, 0x2f, 0x6c, 0x79, 0xb3,
        0x81, 0x2c, 0x81, 0xad, 0xda, 0xdf, 0x48, 0xba, 0x24, 0x36, 0x0a, 0xf2, 0xfa, 0xb8, 0xb4, 0x64,
        0x98, 0xc5, 0xbf, 0xc9, 0xbe, 0xbd, 0x19, 0x8e, 0x26, 0x8c, 0x3b, 0xa7, 0x09, 0xe0, 0x42, 0x14,
        0x68, 0x00, 0x7b, 0xac, 0xb2, 0xdf, 0x33, 0x16, 0x96, 0xe9, 0x39, 0xe4, 0x6c, 0x51, 0x8d, 0x80,
        0xc8, 0x14, 0xe2, 0x04, 0x76, 0xa9, 0xfb, 0x8a, 0x50, 0x25, 0xc0, 0x2d, 0x59, 0xc5, 0x82, 0x39,
        0xde, 0x13, 0x69, 0x67, 0x6c, 0xcc, 0x5a, 0x71, 0xfa, 0x25, 0x63, 0x95, 0x96, 0x74, 0xee, 0x15,
        0x58, 0x86, 0xca, 0x5d, 0x2e, 0x2f, 0x31, 0xd7, 0x7e, 0x0a, 0xf1, 0xfa, 0x27, 0xcf, 0x73, 0xc3, 
        0x74, 0x9c, 0x47, 0xab, 0x18, 0x50, 0x1d, 0xda, 0xe2, 0x75, 0x7e, 0x4f, 0x74, 0x01, 0x90, 0x5a,
        0xca, 0xfa, 0xaa, 0xe3, 0xe4, 0xd5, 0x9b, 0x34, 0x9a, 0xdf, 0x6a, 0xce, 0xbd, 0x10, 0x19, 0x0d,
        0xfe, 0x48, 0x90, 0xd1, 0xe6, 0x18, 0x8d, 0x0b, 0x04, 0x6d, 0xf3, 0x44, 0x70, 0x6c, 0x63, 0x1e
    };

    uint8_t round_keys[240];
    KeyExpansion(key,round_keys,KEY_SIZE_BITS_256);

    // printf("Generated Round Keys:\n");
    // print_round_keys(round_keys, 14);
    ASSERT(memcmp(round_keys, expected_round_keys, sizeof(expected_round_keys)) == 0, "KeyExpansion for AES-256 failed.");
    return true;
}
//Inverse functions:
bool test_InvCipher() {
    const char *state_hex = "32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34";
    const char *key_hex = "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c";

    state_t original_state, state;
    key_128 key;

    // Convert input hex strings to state and key
    hex_line_to_state(state_hex, original_state);
    hex_line_to_key(key_hex, key, KEY_SIZE_BYTES_128);

    // Make a copy of the original state to encrypt and decrypt
    memcpy(state, original_state, sizeof(state_t));
    // printf("og state:\n");
    // print_state(state);
    // Perform encryption
    Cipher(state, key, KEY_SIZE_BITS_128);
    // printf("state after cipher:\n");
    // print_state(state);
    // Perform decryption
    InvCipher(state, key, KEY_SIZE_BITS_128);
    // printf("state after invCipher\n");
    // print_state(state);
    // Compare the decrypted state with the original state
    ASSERT(memcmp(state, original_state, sizeof(state_t)) == 0, "InvCipher failed.");

    return true;
}
bool test_InvSubBytes() {
    state_t state = {
    {0xd4, 0xe0, 0xb8, 0x1e},
    {0x27, 0xbf, 0xb4, 0x41},
    {0x11, 0x98, 0x5d, 0x52},
    {0xae, 0xf1, 0xe5, 0x30}
    };
    state_t expected_state = {
    {0x19, 0xa0, 0x9a, 0xe9},
    {0x3d, 0xf4, 0xc6, 0xf8},
    {0xe3, 0xe2, 0x8d, 0x48},
    {0xbe, 0x2b, 0x2a, 0x08}
    };

    InvSubBytes(state);

    ASSERT(memcmp(state, expected_state, sizeof(state_t)) == 0, "InvSubBytes failed.");
    return true;
}
bool test_InvShiftRows() {
    state_t state = {
    {0x00, 0x01, 0x02, 0x03},
    {0x11, 0x12, 0x13, 0x10},
    {0x22, 0x23, 0x20, 0x21},
    {0x33, 0x30, 0x31, 0x32}
    };
    state_t expected_state = {
    {0x00, 0x01, 0x02, 0x03},
    {0x10, 0x11, 0x12, 0x13},
    {0x20, 0x21, 0x22, 0x23},
    {0x30, 0x31, 0x32, 0x33}
    };

    InvShiftRows(state);

    ASSERT(memcmp(state, expected_state, sizeof(state_t)) == 0, "InvShiftRows failed.");
    return true;
}
bool test_InvMixColumns() {
    state_t state = {
        {0x04, 0xe0, 0x48, 0x28}, 
        {0x66, 0xcb, 0xf8, 0x06}, 
        {0x81, 0x19, 0xd3, 0x26}, 
        {0xe5, 0x9a, 0x7a, 0x4c}
    };
    state_t expected_state = {
        {0xd4, 0xe0, 0xb8, 0x1e}, 
        {0xbf, 0xb4, 0x41, 0x27}, 
        {0x5d, 0x52, 0x11, 0x98}, 
        {0x30, 0xae, 0xf1, 0xe5}
    };
    InvMixColumns(state);
    //print_state(state);
    ASSERT(memcmp(state, expected_state, sizeof(state_t)) == 0, "InvMixColumns failed.");
    return true;
}
#pragma endregion
#pragma region ---------- Internal AES Utilities Functions ----------
bool test_gf_multiply() {
    uint8_t a, b, expected, result;

    a = 0xFF;
    b = 0xFF;
    expected = 0x13;
    result = gf_multiply(a,b);
    // printf("result 0x%02X\n", expected);
    // printf("result 0x%02X\n", result);
    ASSERT(expected == result, "mul failed");

    a = 0x01;
    b = 0x01;
    expected = 0x01;  //mul by 1
    ASSERT(expected == gf_multiply(a,b),"mul failed");

    a = 0x80;
    b = 0x80;
    expected = 0x9a;  // overflow with reduction
    ASSERT(expected == gf_multiply(a,b),"mul failed");
    return true;
}
bool test_mix_single_column() {
    uint8_t input_col[4] = {0xdb, 0x13, 0x53, 0x45};
    uint8_t expected_col[4] = {0x8e, 0x4d, 0xa1, 0xbc}; 

    mix_single_column(input_col, mix_matrix);

    // printf("Output column after mix_single_column:\n");
    // for (int i = 0; i < 4; i++) {
    //     printf("0x%02x ", input_col[i]);
    // }
    // printf("\n");

    ASSERT(memcmp(input_col, expected_col, 4) == 0, "mix_single_column produced incorrect results");

    return true;
}
bool test_RotWord() {
    uint8_t input[4] = {0x09, 0xcf, 0x4f, 0x3c};
    uint8_t expected_output[4] = {0xcf, 0x4f, 0x3c, 0x09};
    uint8_t output[4];

    memcpy(output, input, 4);
    RotWord(output);

    ASSERT(memcmp(output, expected_output, 4) == 0, "RotWord failed.");
    return true;
}
bool test_SubWord() {
    uint8_t input[4] = {0x19, 0xa0, 0x9a, 0xe9};
    uint8_t expected_output[4] = {0xd4, 0xe0, 0xb8, 0x1e};
    uint8_t output[4];

    memcpy(output, input, 4);
    SubWord(output);

    ASSERT(memcmp(output, expected_output, 4) == 0, "SubWord failed.");
    return true;
}
#pragma endregion
#pragma region ---------- Utilities Functions ----------
bool test_stringToState() {
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
bool test_stateToString() {
    state_t state = {
        {0x61, 0x62, 0x63, 0x64}, // 'a', 'b', 'c', 'd'
        {0x65, 0x66, 0x67, 0x68}, // 'e', 'f', 'g', 'h'
        {0x69, 0x6a, 0x6b, 0x6c}, // 'i', 'j', 'k', 'l'
        {0x6d, 0x6e, 0x6f, 0x70}  // 'm', 'n', 'o', 'p'
    };
    char given_str[BLOCK_SIZE_BYTES + 1] = {0};
    char expected_output[] = "abcdefghijklmnop";
    
    stateToString(state, given_str);

    // printf("Actual string:\n");
    // for (int i = 0; i < 16; i++)
    // {
    //     printf("%c", given_str[i]);
    // }printf("\n");
    // printf("Expected string:\n");
    // printf("%s\n", expected_output);

    ASSERT(memcmp(given_str, expected_output, BLOCK_SIZE_BYTES) == 0, "stateToString failed.");
    return true;
}
#pragma endregion

int main() {
    printf("\033[0;35m");
    printf("Starting AES tests...\n");
    printf("\033[0m");

    // Run tests
    RUN_TEST(test_stringToState);
    RUN_TEST(test_stateToString);
    RUN_TEST(test_create_key);
    RUN_TEST(test_RotWord);
    RUN_TEST(test_SubWord);
    RUN_TEST(test_KeyExpansion_128);
    RUN_TEST(test_KeyExpansion_192);
    RUN_TEST(test_keyExpansion_256);
    RUN_TEST(test_AddRoundKey);
    RUN_TEST(test_SubBytes);
    RUN_TEST(test_ShiftRows);
    RUN_TEST(test_gf_multiply);
    RUN_TEST(test_mix_single_column);
    RUN_TEST(test_MixColumns);
    RUN_TEST(test_Cipher);
    RUN_TEST(test_InvSubBytes);
    RUN_TEST(test_InvShiftRows);
    RUN_TEST(test_InvMixColumns);
    RUN_TEST(test_InvCipher);
    RUN_TEST(test_encrypt_text_ECB);
    printf("\033[0;35m");
    printf("All tests completed.\n");
    printf("\033[0m");
    return 0;
}