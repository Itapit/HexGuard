#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "aes.h"
#define state_row_len 4
#define state_col_len 4
#define Nb 4  //pretty sure the Nb represent the number of cols in the state

#define AES_BLOCK_SIZE 16  // Block size in bytes
#define AES_KEY_SIZE_128 16 // Key size in bytes for AES-128
#define AES_KEY_SIZE_192 24 // Key size in bytes for AES-192
#define AES_KEY_SIZE_256 32 // Key size in bytes for AES-256

// AES S-box
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};
// Constant matrix for keyExpansion
static const uint8_t Rcon[16] = {
    0x00, 0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80, 0x1B,
    0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A
};
// Constant matrix for MixColumns transformation
static const uint8_t mix_matrix[4][4] = {
    {0x02, 0x03, 0x01, 0x01},
    {0x01, 0x02, 0x03, 0x01},
    {0x01, 0x01, 0x02, 0x03},
    {0x03, 0x01, 0x01, 0x02}
};
// ------------- Public Functions (DLL Main Functions) -------------
void create_key(uint8_t *key, size_t key_size){  // key_size accept 128 192 256
    //TODO fix the generation to an actual random keys

    if (key_size != 128 && key_size != 192 && key_size != 256){
        printf("key size is invalid");
        return;
    }
    for (size_t i = 0; i < key_size / 8; i++) {
        key[i] = rand() & 0xFF;
    }
}
void create_iv(uint8_t *key){
    //TODO fix the generation to an actual random iv
    for (int i = 0; i < AES_KEY_SIZE_128; i++) {
        key[i] = rand() & 0xFF;
    }
}
// ------------- Internal AES Core Functions -------------
void Cipher(state_t state, const uint8_t *key, size_t key_size) {
    int Nr;  // Number of rounds
    int Nk = key_size / 32;

    // Determine number of rounds based on key size
    if (Nk == 4) {
        Nr = 10;  // AES-128
    } else if (Nk == 6) {
        Nr = 12;  // AES-192
    } else if (Nk == 8) {
        Nr = 14;  // AES-256
    } else {
        printf("Invalid key size.\n");
        return;
    }
    int round_keys_size = AES_BLOCK_SIZE * (Nr + 1);
    uint8_t *round_keys = (uint8_t *)calloc(round_keys_size, sizeof(uint8_t));

    if (round_keys == NULL) {
        printf("Memory allocation failed.\n");
        return;
    }
    // Generate round keys
    KeyExpansion(key, round_keys, key_size);

    // printf("\033[0;35m");
    // printf("input state:\n");
    // printf("\033[0m");
    // print_state(state);

    // Initial Round
    AddRoundKey(state, &round_keys[0]);

    // printf("\033[0;35m");
    // printf("round number 1\n");
    // printf("\033[0m");
    // print_state(state);

    // Main Rounds
    for (int round = 1; round < Nr; round++) {
        SubBytes(state);
        // printf("\033[0;35m");
        // printf("After Subbytes round number %d:\n", round+1);
        // printf("\033[0m");
        // print_state(state);
        ShiftRows(state);
        // printf("\033[0;35m");
        // printf("After ShiftRows round number %d:\n", round+1);
        // printf("\033[0m");
        // print_state(state);
        MixColumns(state);
        // printf("\033[0;35m");
        // printf("After MixColumns round number %d:\n", round+1);
        // printf("\033[0m");
        // print_state(state);
        AddRoundKey(state, &round_keys[round * AES_BLOCK_SIZE]);
        // printf("\033[0;35m");
        // printf("round number %d:\n", round+1);
        // printf("\033[0m");
        // print_state(state);
    }
    // Final Round
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, &round_keys[Nr * AES_BLOCK_SIZE]);
    // printf("\033[0;35m");
    // printf("final round\n");
    // printf("\033[0m");
    // print_state(state);
    
    free(round_keys);
}
void AddRoundKey(state_t state, const uint8_t *round_key) {
    for (int col = 0; col < 4; col++) {
        for (int row = 0; row < 4; row++) {
            state[row][col] ^= round_key[col * 4 + row];
        }
    }
}
void SubBytes(state_t state) {
    for (int col = 0; col < 4; col++) {
        for (int row = 0; row < 4; row++) {
            state[row][col] = sbox[state[row][col]];
        }
    }
}
void ShiftRows(state_t state) {
    uint8_t temp[4];

    // Row 1 (shift left by 1)
    for (int col = 0; col < 4; col++) {
        temp[col] = state[1][(col + 1) % 4];
    }
    for (int col = 0; col < 4; col++) {
        state[1][col] = temp[col];
    }

    // Row 2 (shift left by 2)
    for (int col = 0; col < 4; col++) {
        temp[col] = state[2][(col + 2) % 4];
    }
    for (int col = 0; col < 4; col++) {
        state[2][col] = temp[col];
    }

    // Row 3 (shift left by 3)
    for (int col = 0; col < 4; col++) {
        temp[col] = state[3][(col + 3) % 4];
    }
    for (int col = 0; col < 4; col++) {
        state[3][col] = temp[col];
    }
}
void KeyExpansion(const uint8_t *key, uint8_t *key_schedule, size_t key_size) {
    int Nk = key_size / 32;   //number of words in the key
    int Nr; //number of rounds
    if(Nk == 4){
        Nr = 10;}
    else if (Nk == 6){
        Nr = 12;}
    else if (Nk == 8){
        Nr = 14;}
    else{
        printf("Invalid key size. Supported sizes are 128, 192, and 256 bits.\n");
        return;
    }
    // printf("Nk: %d\n", Nk);
    // printf("Nr: %d\n", Nr);
    uint8_t temp[4];
    int i = 0;

    // Copy the original key to the first Nk words of the key schedule
    memcpy(key_schedule, key, Nk * 4);

    // Generate the remaining words
    for (i = Nk; i < Nb * (Nr + 1); i++) {
        memcpy(temp, &key_schedule[(i - 1) * 4], 4);

        if (i % Nk == 0) {
            RotWord(temp);
            SubWord(temp);
            temp[0] ^= Rcon[i / Nk]; // Apply Rcon directly
        }
        else if (Nk > 6 && i % Nk == 4) {
            SubWord(temp);
        }

        for (int j = 0; j < 4; j++) {
            key_schedule[i * 4 + j] = key_schedule[(i - Nk) * 4 + j] ^ temp[j];
        }
    }
}
void MixColumns(state_t state) {
    uint8_t col[4];
    for (int col_idx = 0; col_idx < 4; col_idx++) {
        // Extract column
        for (int row = 0; row < 4; row++) {
            col[row] = state[row][col_idx];
        }

        // Mix column
        mix_single_column(col);

        // Write back column
        for (int row = 0; row < 4; row++) {
            state[row][col_idx] = col[row];
        }
    }
}

// ------------- Internal AES Utilities Functions -------------
uint8_t gf_multiply(uint8_t a, uint8_t b) {
    /*
    Performs multiplication in the finite field GF(2^8) using the
    AES irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x1B).
    
    The function implements finite field multiplication by iteratively
    checking each bit of the multiplier `b`. If a bit in `b` is set (1),
    the corresponding value of `a` (shifted appropriately) is XORed 
    into the result `p`. The polynomial is reduced modulo the AES 
    irreducible polynomial when necessary to ensure the result stays 
    within GF(2^8). 

    Steps:
    1. Initialize the product `p` to 0.
    2. Repeat the following for 8 iterations (one for each bit of `b`):
       a. If the least significant bit (LSB) of `b` is 1, XOR `p` with `a`.
       b. Check if the most significant bit (MSB) of `a` is set before shifting.
       c. Shift `a` left by one bit. If the MSB was set, XOR `a` with 0x1B 
          to perform modular reduction.
       d. Shift `b` right by one bit to process the next bit.
    3. Return the final value of `p`, which is the product in GF(2^8).
    */
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1)  //LSB of b is set aka LSB equal 1
            p ^= a;
        
        uint8_t hi_bit_set = (a & 0x80);  //MSB of a
        a <<= 1;
        
        if (hi_bit_set)
            a ^= 0x1B;   // x^8 + x^4 + x^3 + x + 1
        
        b >>= 1;
    }
    return p;
}
void mix_single_column(uint8_t* col) {
    uint8_t temp[4];
    for (int i = 0; i < 4; i++) {
        temp[i] = gf_multiply(mix_matrix[i][0], col[0]) ^
                  gf_multiply(mix_matrix[i][1], col[1]) ^
                  gf_multiply(mix_matrix[i][2], col[2]) ^
                  gf_multiply(mix_matrix[i][3], col[3]);
    }
    for (int i = 0; i < 4; i++) {
        col[i] = temp[i];
    }
}
void RotWord(uint8_t *word) {
    uint8_t temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}
void SubWord(uint8_t *word) {
    for (int i = 0; i < 4; i++) {
        word[i] = sbox[word[i]];
    }
}
// ------------- Utilities Functions -------------
void hex_line_to_state(const char *hex_line, state_t state) {
    // Temporary buffer for storing parsed bytes
    uint8_t temp[AES_BLOCK_SIZE];
    int byte_count = 0;

    // Parse the input hex line
    const char *pos = hex_line;
    while (*pos && byte_count < AES_BLOCK_SIZE) {
        if (*pos == ' ') {
            pos++;  // Skip spaces
            continue;
        }

        // Convert two hex characters into a single byte
        char byte_str[3] = {pos[0], pos[1], '\0'};
        temp[byte_count++] = (uint8_t)strtol(byte_str, NULL, 16);

        pos += 2;  // Move to the next pair of hex digits
    }

    // Convert temporary array to column-major state
    for (int col = 0; col < 4; col++) {
        for (int row = 0; row < 4; row++) {
            state[row][col] = temp[col * 4 + row];
        }
    }
}
void hex_line_to_key(const char *hex_line, uint8_t *key, size_t key_size) {
    // Ensure the key size is valid
    if (key_size != 16 && key_size != 24 && key_size != 32) {
        printf("Invalid key size. Supported sizes are 16, 24, or 32 bytes.\n");
        return;
    }
    size_t byte_count = 0;  // Changed from int to size_t

    // Parse the input hex line
    const char *pos = hex_line;
    while (*pos && byte_count < key_size) {
        if (*pos == ' ') {
            pos++;  // Skip spaces
            continue;
        }

        // Convert two hex characters into a single byte
        char byte_str[3] = {pos[0], pos[1], '\0'};
        key[byte_count++] = (uint8_t)strtol(byte_str, NULL, 16);

        pos += 2;  // Move to the next pair of hex digits
    }

    if (byte_count != key_size) {
        printf("Warning: Parsed key size (%zu bytes) does not match the expected size (%zu bytes).\n", byte_count, key_size);
    }
}

void stringToState(const char *input, state_t state){
    //TODO add padding
    if (strlen(input) != AES_BLOCK_SIZE) {
        return;
    }
    for (int row = 0; row < state_row_len; row++) {
        for (int col = 0; col < state_col_len; col++) {
            state[row][col] = input[row * state_row_len + col];
        }
    }  
}
void stateToString(const state_t state, char *output){
    for (int row = 0; row < state_row_len; row++){
        for (int col = 0; col < state_col_len; col++){
            output[row * 4 + col] = state[row][col];   
        }
    }
    output[AES_BLOCK_SIZE] = '\0';
}
void print_state(const state_t state) {
    printf("stat (col-Major Order):\n");
    for (int row = 0; row < state_row_len; row++) {
        for (int col = 0; col < state_col_len; col++) {
            printf("0x%02x ", state[row][col]);
        }
        printf("\n");
    }
}
void print_round_keys(const uint8_t *round_keys, size_t num_rounds) {
    for (size_t round = 0; round <= num_rounds; round++) {
        printf("\033[0;34mRound %zu:\033[0m\n", round);
        for (size_t row = 0; row < 4; row++) {
            for (size_t col = 0; col < 4; col++) {
                printf("0x%02x ", round_keys[round * 16 + col * 4 + row]);
            }
            printf("\n");
        }
        printf("\n");
    }
}

void print_key(const uint8_t *key, size_t key_size) {
    printf("Key (Row-Major Order):\n");
    for (size_t i = 0; i < key_size; i++) {
        printf("0x%02x ", key[i]);
        if ((i + 1) % 4 == 0) {
            printf("\n");  // Print 4 bytes per row
        }
    }
    printf("\n");
}