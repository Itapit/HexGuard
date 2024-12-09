#ifndef AES_H
#define AES_H

#include <stdint.h>

// AES Constants
#define AES_BLOCK_SIZE 16  // Block size in bytes
#define AES_KEY_SIZE_128 16 // Key size in bytes for AES-128
#define AES_KEY_SIZE_192 24 // Key size in bytes for AES-192
#define AES_KEY_SIZE_256 32 // Key size in bytes for AES-256

typedef uint8_t state_t[4][4];

// Public Functions (DLL Main Functions)
void create_key(uint8_t *key, size_t key_size);
void create_iv(uint8_t *key, size_t iv_size);

void select_mode(const char *mode_name); // Accepts "ECB", "CBC", "CFB", "OFB", or "CTR"

void encrypt_file(const char *file_path, const uint8_t *key, const uint8_t *iv);
void encrypt_text(const char *input_text, char *output_text, const uint8_t *key, const uint8_t *iv);

void decrypt_file(const char *file_path, const uint8_t *key, const uint8_t *iv);
void decrypt_text(const char *input_text, char *output_text, const uint8_t *key, const uint8_t *iv);

// Internal AES Core Functions
void AddRoundKey(state_t state, const uint8_t *round_key);
void SubBytes(state_t state);
void ShiftRows(state_t state);
void MixColumns(state_t state);
void KeyExpansion(const uint8_t *key, uint8_t *expanded_keys, size_t key_size);

// Inverse Operations
void InvSubBytes(state_t state);
void InvShiftRows(state_t state);
void InvMixColumns(state_t state);

// Utilities
void string_to_state(const char *input, state_t state);
void state_to_string(const state_t state, char *output);

// Encryption/Decryption Core
void aes_encrypt_block(const uint8_t *input, uint8_t *output, const uint8_t *key, size_t key_size);
void aes_decrypt_block(const uint8_t *input, uint8_t *output, const uint8_t *key, size_t key_size);



#endif 