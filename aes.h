#ifndef AES_H
#define AES_H

#include <stdint.h>

// AES Constants
#define AES_BLOCK_SIZE 16  // Block size in bytes
#define AES_KEY_SIZE_128 16 // Key size in bytes for AES-128
#define AES_KEY_SIZE_192 24 // Key size in bytes for AES-192
#define AES_KEY_SIZE_256 32 // Key size in bytes for AES-256
#define state_row_len 4
#define state_col_len 4

typedef uint8_t state_t[state_col_len][state_row_len];
typedef uint8_t key_128[16];
typedef uint8_t key_192[24];
typedef uint8_t key_256[32];

// Public Functions (DLL Main Functions)
void create_key(uint8_t *key, size_t key_size);
void create_iv(uint8_t *key);

// void encrypt_file(const char * Mode_of_operation, const char *file_path, const uint8_t *key, const uint8_t *iv); //Accepts CBC CFB OFB PCBC  without iv: ECB CTR
// void encrypt_text(const char * Mode_of_operation, const char *input_text, char *output_text, const uint8_t *key, const uint8_t *iv);  //Accepts CBC CFB OFB PCBC  without iv: ECB CTR

// void decrypt_file(const char * Mode_of_operation, const char *file_path, const uint8_t *key, const uint8_t *iv); //Accepts CBC CFB OFB PCBC without iv: ECB CTR
// void decrypt_text(const char * Mode_of_operation, const char *input_text, char *output_text, const uint8_t *key, const uint8_t *iv); //Accepts CBC CFB OFB PCBC without iv: ECB CTR

// Internal AES Core Functions
void Cipher(state_t state, const uint8_t *key, size_t key_size);
void AddRoundKey(state_t state, const uint8_t *round_key);
void SubBytes(state_t state);
void ShiftRows(state_t state);
void MixColumns(state_t state);
void KeyExpansion(const uint8_t *key, uint8_t *key_schedule, size_t key_size);

// Inverse Operations
void InvSubBytes(state_t state);
void InvShiftRows(state_t state);
void InvMixColumns(state_t state);

// Internal AES Utilities Functions
uint8_t gf_multiply(uint8_t a, uint8_t b);
void mix_single_column(uint8_t* col);
void RotWord(uint8_t *word);
void SubWord(uint8_t *word);

// Utilities
void hex_line_to_state(const char *hex_line, state_t state);
void hex_line_to_key(const char *hex_line, uint8_t *key, size_t key_size);
void stringToState(const char *input, state_t state);
void stateToString(const state_t state, char *output);
void print_state(const state_t state);
void print_round_keys(const uint8_t *round_keys, size_t num_rounds);
void print_key(const uint8_t *key, size_t key_size);
// Encryption/Decryption Core
void aes_encrypt_block(const uint8_t *input, uint8_t *output, const uint8_t *key, size_t key_size);
void aes_decrypt_block(const uint8_t *input, uint8_t *output, const uint8_t *key, size_t key_size);


#endif 