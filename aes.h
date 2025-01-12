#ifndef AES_H
#define AES_H

#pragma region ---------- PreProcessor and typedef ----------
#include <stdint.h>

// AES Constants
#define BLOCK_SIZE_BYTES 16  // Block size in bytes
#define KEY_SIZE_BYTES_128 16 // Key size in bytes for AES-128
#define KEY_SIZE_BYTES_192 24 // Key size in bytes for AES-192
#define KEY_SIZE_BYTES_256 32 // Key size in bytes for AES-256

#define KEY_SIZE_BITS_128 128 // Key size in bits for AES-128
#define KEY_SIZE_BITS_192 192 // Key size in bits for AES-192
#define KEY_SIZE_BITS_256 256 // Key size in bits for AES-256

#define state_row_len 4
#define state_col_len 4

typedef uint8_t state_t[state_col_len][state_row_len];
typedef uint8_t key_128[16];
typedef uint8_t key_192[24];
typedef uint8_t key_256[32];
typedef uint8_t iv_def[16]; 
extern const uint8_t mix_matrix[4][4];
#pragma endregion
#pragma region ---------- Public Functions (DLL Main Functions) ----------
// Public Functions (DLL Main Functions)
void create_key(uint8_t *key, size_t key_size);
void create_iv(uint8_t *key);

// void encrypt_file(const char * Mode_of_operation, const char *file_path, const uint8_t *key, const uint8_t *iv); //Accepts CBC CFB OFB PCBC  or without iv: ECB CTR
void encrypt_text(const char * Mode_of_operation, const char *input_text, char *output_text, size_t *output_len, const uint8_t *key, const size_t key_size, const uint8_t *iv);//Accepts CBC CFB OFB PCBC  without iv: ECB CTR
void decrypt_text(const char * Mode_of_operation, const char *input_text, size_t input_len, char *output_text, const uint8_t *key, const size_t key_size, const uint8_t *iv);
void encrypt_file(const char *input_file_path, const char *output_file_path, const uint8_t *key, const size_t key_size, const uint8_t *iv);
void decrypt_file(const char *input_file_path, const char *output_file_path, const uint8_t *key, const size_t key_size, const uint8_t *iv);
// void decrypt_file(const char * Mode_of_operation, const char *file_path, const uint8_t *key, const uint8_t *iv); //Accepts CBC CFB OFB PCBC without iv: ECB CTR
// void decrypt_text(const char * Mode_of_operation, const char *input_text, char *output_text, const uint8_t *key, const uint8_t *iv); //Accepts CBC CFB OFB PCBC without iv: ECB CTR
#pragma endregion
#pragma region ---------- Modes of operations Functions ----------
void encrypt_text_ECB(const char *input_text,char * output_text,const uint8_t *key, size_t key_size, size_t input_len);
void encrypt_text_CBC(const char *input_text,char * output_text,const uint8_t *key, size_t key_size, const uint8_t *iv, size_t input_len);
void encrypt_text_OFB(const char *input_text,char * output_text,const uint8_t *key, size_t key_size, const uint8_t *iv, size_t input_len);
void encrypt_text_CFB(const char *input_text,char * output_text,const uint8_t *key, size_t key_size, const uint8_t *iv, size_t input_len);

void decrypt_text_ECB(const char *input_text, char *output_text, const uint8_t *key, size_t key_size, size_t input_len);
void decrypt_text_CBC(const char *input_text, char *output_text, const uint8_t *key, size_t key_size, const uint8_t *iv, size_t input_len);

#pragma endregion
#pragma region ---------- Internal AES Core Functions ----------
// Internal AES Core Functions
void Cipher(state_t state, const uint8_t *key, size_t key_size);
void AddRoundKey(state_t state, const uint8_t *round_key);
void SubBytes(state_t state);
void ShiftRows(state_t state);
void MixColumns(state_t state);
void KeyExpansion(const uint8_t *key, uint8_t *key_schedule, size_t key_size);

// Inverse Operations
void InvCipher(state_t state, const uint8_t *key, size_t key_size);
void InvSubBytes(state_t state);
void InvShiftRows(state_t state);
void InvMixColumns(state_t state);
#pragma endregion
#pragma region ---------- Internal AES Utilities Functions ----------
// Internal AES Utilities Functions
uint8_t gf_multiply(uint8_t a, uint8_t b);
void mix_single_column(uint8_t* col, const uint8_t matrix[4][4]);
void RotWord(uint8_t *word);
void SubWord(uint8_t *word);
#pragma endregion
#pragma region ---------- Utilities Functions ----------
// Utilities
void hex_line_to_state(const char *hex_line, state_t state);
void hex_line_to_key(const char *hex_line, uint8_t *key, size_t key_size);
void stringToState(const char *input, state_t state);
void stateToString(const state_t state, char *output);
void print_state(const state_t state);
void print_round_keys(const uint8_t *round_keys, size_t num_rounds);
void print_key(const uint8_t *key, size_t key_size);
void add_pkcs7_padding(const char *input, size_t input_len, char *output, size_t *padded_len);
void remove_pkcs7_padding(char *input, int input_len, size_t *unpadded_len);
void xor_state_state(state_t state_primary, const state_t state);
#pragma endregion

#endif 