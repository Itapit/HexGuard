#pragma region ---------- PreProcessor and global variables ----------
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <io.h>

#ifdef _WIN32
    #include <windows.h>
    #include <wincrypt.h>
#else
    #include <fcntl.h>
    #include <unistd.h>
#endif

#include "aes.h"
#define state_row_len 4
#define state_col_len 4
#define Nb 4  //pretty sure the Nb represent the number of cols in the state

#define BLOCK_SIZE_BYTES 16  // Block size in bytes
#define KEY_SIZE_BYTES_128 16 // Key size in bytes for AES-128
#define KEY_SIZE_BYTES_192 24 // Key size in bytes for AES-192
#define KEY_SIZE_BYTES_256 32 // Key size in bytes for AES-256

#define KEY_SIZE_BITS_128 128 // Key size in bits for AES-128
#define KEY_SIZE_BITS_192 192 // Key size in bits for AES-192
#define KEY_SIZE_BITS_256 256 // Key size in bits for AES-256

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
// AES inverse s-box
static const uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};
// Constant matrix for keyExpansion
static const uint8_t Rcon[16] = {
    0x00, 0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80, 0x1B,
    0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A
};
// Constant matrix for MixColumns transformation
const uint8_t mix_matrix[4][4] = {
    {0x02, 0x03, 0x01, 0x01},
    {0x01, 0x02, 0x03, 0x01},
    {0x01, 0x01, 0x02, 0x03},
    {0x03, 0x01, 0x01, 0x02}
};
// Constant matrix for inverse MixColumns transformation
static const uint8_t inv_mix_matrix[4][4] = {
    {0x0E, 0x0B, 0x0D, 0x09},
    {0x09, 0x0E, 0x0B, 0x0D},
    {0x0D, 0x09, 0x0E, 0x0B},
    {0x0B, 0x0D, 0x09, 0x0E}
};
#pragma endregion
#pragma region ---------- Public Functions (DLL Main Functions) ----------
// ------------- Public Functions (DLL Main Functions) -------------

AES_API void create_key(uint8_t *key, size_t key_size_bits) {
    // key_size_bits is expected as 128, 192, or 256 bits
    if (key_size_bits != KEY_SIZE_BITS_128 &&
        key_size_bits != KEY_SIZE_BITS_192 &&
        key_size_bits != KEY_SIZE_BITS_256) {
        printf("Invalid key size.\n");
        return;
    }
    
    size_t key_size_bytes = key_size_bits / 8;
    if (!get_random_bytes(key, key_size_bytes)) {
        fprintf(stderr, "Error generating secure key.\n");
        return;
    }
}
AES_API void create_iv(uint8_t *iv) {
    // For AES, the IV is 16 bytes (128 bits)
    if (!get_random_bytes(iv, KEY_SIZE_BYTES_128)) {
        printf("Error generating secure IV.\n");
        return;
    }
}

AES_API void encrypt_text(const char * Mode_of_operation, const char *input_text, char *output_text, size_t *output_len, const uint8_t *key, const size_t key_size, const uint8_t *iv) {
    int input_len = strlen(input_text);
    char *padded_input = (char *)malloc(input_len + BLOCK_SIZE_BYTES);  // Ensure space for padding
    if (!padded_input) {
        //TODO add actual error
        printf("Memory allocation failed.\n");
        return;
    }

    add_pkcs7_padding(input_text, input_len, padded_input, output_len);
    if (strcmp(Mode_of_operation, "ECB") == 0) {
        encrypt_text_ECB(padded_input, output_text, key, key_size, *output_len);
    } 
    else if (strcmp(Mode_of_operation, "CBC") == 0) {
        encrypt_text_CBC(padded_input, output_text, key, key_size, iv, *output_len);
    }
    else if (strcmp(Mode_of_operation, "CFB") == 0) {
        encrypt_text_CFB(padded_input, output_text, key, key_size, iv, *output_len);
    }
    // else if (strcmp(Mode_of_operation, "OFB") == 0) {
    //     encrypt_text_OFB(padded_input, output_text, key, key_size, iv, padded_len);
    // }
    else {
        //TODO add actual error
        printf("Invalid mode of operation: %s\n", Mode_of_operation);
    }
    free(padded_input);
}
AES_API void decrypt_text(const char * Mode_of_operation, const char *input_text, size_t input_len, char *output_text, const uint8_t *key, const size_t key_size, const uint8_t *iv) {
    size_t unpadded_len = 0;
    if (strcmp(Mode_of_operation, "ECB") == 0) {
        decrypt_text_ECB(input_text, output_text, key, key_size, input_len);
    } 
    else if (strcmp(Mode_of_operation, "CBC") == 0) {
        decrypt_text_CBC(input_text, output_text, key, key_size, iv, input_len);
    }
    else if (strcmp(Mode_of_operation, "CFB") == 0) {
        decrypt_text_CFB(input_text, output_text, key, key_size, iv, input_len);
    }
    // else if (strcmp(Mode_of_operation, "OFB") == 0) {
    //     
    // }
    else {
        //TODO add actual error
        printf("Invalid mode of operation: %s\n", Mode_of_operation);
    }

    remove_pkcs7_padding(output_text, input_len, &unpadded_len); // handle the removal of the padding and adding null terminator
}
AES_API void encrypt_file(const char * Mode_of_operation, const char *input_file_path, const char *output_file_path, const uint8_t *key, const size_t key_size, const uint8_t *iv) {
    
    FILE *input_file = fopen(input_file_path, "rb");
    if (!input_file) {
        printf("Failed to open input file");
        return;
    }

    FILE *output_file = fopen(output_file_path, "wb");
    if (!output_file) {
        printf("Failed to open output file");
        fclose(input_file);
        return;
    }
    if (strcmp(Mode_of_operation, "ECB") == 0) {
        encrypt_file_ECB(input_file, output_file, key, key_size, iv);
    } 
    else if (strcmp(Mode_of_operation, "CBC") == 0) {
        encrypt_file_CBC(input_file, output_file, key, key_size, iv);
    }
    else if (strcmp(Mode_of_operation, "CFB") == 0) {
        encrypt_file_CFB(input_file, output_file, key, key_size, iv);
    }
    // else if (strcmp(Mode_of_operation, "OFB") == 0) {
    //     encrypt_file_OFB(input_file, output_file, key, key_size, iv);
    // }
    else {
        //TODO add actual error
        printf("Invalid mode of operation: %s\n", Mode_of_operation);
    }

    fclose(input_file);
    fclose(output_file);
}
AES_API void decrypt_file(const char  *Mode_of_operation, const char *input_file_path, const char *output_file_path, const uint8_t *key, const size_t key_size, const uint8_t *iv) {
    FILE *input_file = fopen(input_file_path, "rb");
    if (!input_file) {
        perror("Failed to open input file");
        return;
    }

    FILE *output_file = fopen(output_file_path, "wb+");
    if (!output_file) {
        perror("Failed to open output file");
        fclose(input_file);
        return;
    }

    size_t last_block_size = 0;
    if (strcmp(Mode_of_operation, "ECB") == 0) {
        last_block_size = decrypt_file_ECB(input_file, output_file, key, key_size, iv);
    } 
    else if (strcmp(Mode_of_operation, "CBC") == 0) {
        last_block_size = decrypt_file_CBC(input_file, output_file, key, key_size, iv);
    }
    else if (strcmp(Mode_of_operation, "CFB") == 0) {
        last_block_size = decrypt_file_CFB(input_file, output_file, key, key_size, iv);
    }
    else {
        printf("Invalid mode of operation: %s\n", Mode_of_operation);
        fclose(input_file);
        fclose(output_file);
        return;
    }

    // Handle unpadding for the last block
    if (last_block_size == BLOCK_SIZE_BYTES) {
        uint8_t decrypted_buffer[BLOCK_SIZE_BYTES];
        fseek(output_file, -BLOCK_SIZE_BYTES, SEEK_END);
        fread(decrypted_buffer, 1, BLOCK_SIZE_BYTES, output_file);

        size_t unpadded_len;
        remove_pkcs7_padding((char *)decrypted_buffer, BLOCK_SIZE_BYTES, &unpadded_len);

        fseek(output_file, -BLOCK_SIZE_BYTES, SEEK_END);
        fwrite(decrypted_buffer, 1, unpadded_len, output_file);

        int fd = fileno(output_file);
        if (_chsize(fd, ftell(output_file)) != 0) {
            perror("Failed to truncate file");
        }
    }

    fclose(input_file);
    fclose(output_file);
}

#pragma endregion
#pragma region ---------- Modes of operations Functions ----------
void encrypt_text_ECB(const char *input_text,char * output_text,const uint8_t *key, size_t key_size, size_t input_len){
    state_t buffer_State;
    for (size_t i = 0; i < input_len; i += BLOCK_SIZE_BYTES) {
        // Convert the current 16-byte block to AES state
        stringToState(input_text + i, buffer_State);

        // Encrypt the block using the Cipher function
        Cipher(buffer_State, key, key_size);

        // Convert the encrypted state back to string format
        stateToString(buffer_State, output_text + i);
    }
}
void encrypt_text_CBC(const char *input_text,char * output_text,const uint8_t *key, size_t key_size, const uint8_t *iv, size_t input_len) {
    state_t buffer_current_state;
    state_t buffer_previous_state;
    memcpy(buffer_previous_state, iv, sizeof(iv));
    
    for (size_t i = 0; i < input_len; i += BLOCK_SIZE_BYTES) {
        // Convert the current 16-byte block to AES state
        stringToState(input_text + i, buffer_current_state);
        //xor the previous state with the current in order to implement CBC
        xor_state_state(buffer_current_state, buffer_previous_state);
        // Encrypt the block using the Cipher function
        Cipher(buffer_current_state, key, key_size);
        memcpy(buffer_previous_state, buffer_current_state, sizeof(buffer_current_state));
        // Convert the encrypted state back to string format
        stateToString(buffer_current_state, output_text + i);
    }
}
void encrypt_text_CFB(const char *input_text, char *output_text, const uint8_t *key, size_t key_size, const uint8_t *iv, size_t input_len) {
    uint8_t shift_register[BLOCK_SIZE_BYTES];
    uint8_t keystream[BLOCK_SIZE_BYTES];

    // Initialize the shift register with the IV
    memcpy(shift_register, iv, BLOCK_SIZE_BYTES);

    for (size_t i = 0; i < input_len; i += BLOCK_SIZE_BYTES) {
        size_t segment_len = (i + BLOCK_SIZE_BYTES <= input_len) ? BLOCK_SIZE_BYTES : (input_len - i);

        // Encrypt the current shift register to produce the keystream
        state_t state;
        stringToState((char *)shift_register, state);
        Cipher(state, key, key_size);
        stateToString(state, (char *)keystream);

        // XOR the plaintext with the keystream to produce the ciphertext segment
        for (size_t j = 0; j < segment_len; j++) {
            output_text[i + j] = input_text[i + j] ^ keystream[j];
        }

        // Update the shift register with the ciphertext segment
        memcpy(shift_register, &output_text[i], segment_len);
    }
}
void decrypt_text_ECB(const char *input_text,char * output_text,const uint8_t *key, size_t key_size, size_t input_len) {
    state_t buffer_State;
    for (size_t i = 0; i < input_len; i += BLOCK_SIZE_BYTES)
    {
        // Convert the current 16-byte block to AES state
        stringToState(input_text + i, buffer_State);
        // Decrypt the block using the InvCipher function
        InvCipher(buffer_State, key, key_size);
        // Convert the decrypted state back to string format
        stateToString(buffer_State, output_text + i);
    }
}
void decrypt_text_CBC(const char *input_text, char *output_text, const uint8_t *key, size_t key_size, const uint8_t *iv, size_t input_len) {
    // the decryption is reversed, last block first
    state_t buffer_current_state;
    state_t buffer_previous_state;
    for (size_t i = input_len - BLOCK_SIZE_BYTES ; i > BLOCK_SIZE_BYTES; i -= BLOCK_SIZE_BYTES)
    {
        // Convert the current and previous 16-byte block to AES state
        stringToState(input_text + i - BLOCK_SIZE_BYTES, buffer_previous_state);
        stringToState(input_text + i, buffer_current_state);
        // Decrypt the block using the InvCipher function
        InvCipher(buffer_current_state, key, key_size);
        //xor the previous state with the current in order to implement CBC
        xor_state_state(buffer_current_state, buffer_previous_state);
        // Convert the decrypted state back to string format
        stateToString(buffer_current_state, output_text + i);
    }
    memcpy(buffer_previous_state, iv, sizeof(iv));
    stringToState(input_text, buffer_current_state);
    InvCipher(buffer_current_state, key, key_size);
    xor_state_state(buffer_current_state, buffer_previous_state);
    stateToString(buffer_current_state, output_text);
}
void decrypt_text_CFB(const char *input_text, char *output_text, const uint8_t *key, size_t key_size, const uint8_t *iv, size_t input_len) {
    uint8_t shift_register[BLOCK_SIZE_BYTES];
    uint8_t keystream[BLOCK_SIZE_BYTES];

    // Initialize the shift register with the IV
    memcpy(shift_register, iv, BLOCK_SIZE_BYTES);

    for (size_t i = 0; i < input_len; i += BLOCK_SIZE_BYTES) {
        size_t segment_len = (i + BLOCK_SIZE_BYTES <= input_len) ? BLOCK_SIZE_BYTES : (input_len - i);

        // Encrypt the current shift register to produce the keystream
        state_t state;
        stringToState((char *)shift_register, state);
        Cipher(state, key, key_size);
        stateToString(state, (char *)keystream);

        // XOR the ciphertext with the keystream to produce the plaintext segment
        for (size_t j = 0; j < segment_len; j++) {
            output_text[i + j] = input_text[i + j] ^ keystream[j];
        }

        // Update the shift register with the ciphertext segment
        memcpy(shift_register, &input_text[i], segment_len);
    }
}
void encrypt_file_ECB(FILE *input_file, FILE *output_file, const uint8_t *key, const size_t key_size, const uint8_t *iv) {
    uint8_t buffer[BLOCK_SIZE_BYTES];
    uint8_t encrypted_buffer[BLOCK_SIZE_BYTES];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, BLOCK_SIZE_BYTES, input_file)) > 0) {
        // If the block is smaller than BLOCK_SIZE_BYTES, apply padding
        if (bytes_read < BLOCK_SIZE_BYTES) {
            size_t padded_len;
            uint8_t padded_buffer[BLOCK_SIZE_BYTES];
            add_pkcs7_padding((char *)buffer, bytes_read, (char *)padded_buffer, &padded_len);
            memcpy(buffer, padded_buffer, BLOCK_SIZE_BYTES);
        }

        // Encrypt the block using ECB
        state_t state;
        stringToState((char *)buffer, state);
        Cipher(state, key, key_size);
        stateToString(state, (char *)encrypted_buffer);

        // Write the encrypted block to the output file
        if (fwrite(encrypted_buffer, 1, BLOCK_SIZE_BYTES, output_file) != BLOCK_SIZE_BYTES) {
            perror("Failed to write to output file");
            break;
        }
    }
}
void encrypt_file_CBC(FILE *input_file, FILE *output_file, const uint8_t *key, const size_t key_size, const uint8_t *iv) {
    uint8_t buffer[BLOCK_SIZE_BYTES];
    uint8_t encrypted_buffer[BLOCK_SIZE_BYTES];
    uint8_t previous_block[BLOCK_SIZE_BYTES];
    size_t bytes_read;

    // Initialize the previous block with the IV
    memcpy(previous_block, iv, BLOCK_SIZE_BYTES);

    while ((bytes_read = fread(buffer, 1, BLOCK_SIZE_BYTES, input_file)) > 0) {
        // If the block is smaller than BLOCK_SIZE_BYTES, apply padding
        if (bytes_read < BLOCK_SIZE_BYTES) {
            size_t padded_len;
            uint8_t padded_buffer[BLOCK_SIZE_BYTES];
            add_pkcs7_padding((char *)buffer, bytes_read, (char *)padded_buffer, &padded_len);
            memcpy(buffer, padded_buffer, BLOCK_SIZE_BYTES);
        }

        // XOR the current block with the previous block (CBC mode)
        for (size_t i = 0; i < BLOCK_SIZE_BYTES; i++) {
            buffer[i] ^= previous_block[i];
        }

        // Encrypt the block using ECB
        state_t state;
        stringToState((char *)buffer, state);
        Cipher(state, key, key_size);
        stateToString(state, (char *)encrypted_buffer);

        // Update the previous block
        memcpy(previous_block, encrypted_buffer, BLOCK_SIZE_BYTES);

        // Write the encrypted block to the output file
        if (fwrite(encrypted_buffer, 1, BLOCK_SIZE_BYTES, output_file) != BLOCK_SIZE_BYTES) {
            perror("Failed to write to output file");
            break;
        }
    }
}
void encrypt_file_CFB(FILE *input_file, FILE *output_file, const uint8_t *key, const size_t key_size, const uint8_t *iv) {
    uint8_t shift_register[BLOCK_SIZE_BYTES];
    uint8_t keystream[BLOCK_SIZE_BYTES];
    uint8_t buffer[BLOCK_SIZE_BYTES];
    uint8_t ciphertext[BLOCK_SIZE_BYTES];
    size_t bytes_read;

    // Initialize the shift register with the IV
    memcpy(shift_register, iv, BLOCK_SIZE_BYTES);

    while ((bytes_read = fread(buffer, 1, BLOCK_SIZE_BYTES, input_file)) > 0) {
        // Encrypt the current shift register to produce the keystream
        state_t state;
        stringToState((char *)shift_register, state);
        Cipher(state, key, key_size);
        stateToString(state, (char *)keystream);

        // XOR the plaintext with the keystream to produce the ciphertext segment
        for (size_t i = 0; i < bytes_read; i++) {
            ciphertext[i] = buffer[i] ^ keystream[i];
        }

        // Write the ciphertext to the output file
        fwrite(ciphertext, 1, bytes_read, output_file);

        // Update the shift register with the ciphertext segment
        memcpy(shift_register, ciphertext, bytes_read);
    }
}
size_t decrypt_file_ECB(FILE *input_file, FILE *output_file, const uint8_t *key, const size_t key_size, const uint8_t *iv) {
    uint8_t buffer[BLOCK_SIZE_BYTES];
    uint8_t decrypted_buffer[BLOCK_SIZE_BYTES];
    size_t bytes_read;
    size_t last_block_size = 0;

    while ((bytes_read = fread(buffer, 1, BLOCK_SIZE_BYTES, input_file)) > 0) {
        last_block_size = bytes_read;

        // Decrypt the block using ECB
        state_t state;
        stringToState((char *)buffer, state);
        InvCipher(state, key, key_size);
        stateToString(state, (char *)decrypted_buffer);

        fwrite(decrypted_buffer, 1, BLOCK_SIZE_BYTES, output_file);
    }
    return last_block_size;
}
size_t decrypt_file_CBC(FILE *input_file, FILE *output_file, const uint8_t *key, const size_t key_size, const uint8_t *iv) {
    uint8_t buffer[BLOCK_SIZE_BYTES];
    uint8_t decrypted_buffer[BLOCK_SIZE_BYTES];
    uint8_t previous_block[BLOCK_SIZE_BYTES];
    uint8_t temp_block[BLOCK_SIZE_BYTES];
    size_t bytes_read;
    size_t last_block_size = 0;

    memcpy(previous_block, iv, BLOCK_SIZE_BYTES);

    while ((bytes_read = fread(buffer, 1, BLOCK_SIZE_BYTES, input_file)) > 0) {
        last_block_size = bytes_read;

        memcpy(temp_block, buffer, BLOCK_SIZE_BYTES);

        // Decrypt the block using ECB
        state_t state;
        stringToState((char *)buffer, state);
        InvCipher(state, key, key_size);
        stateToString(state, (char *)decrypted_buffer);

        // XOR the decrypted block with the previous block
        for (size_t i = 0; i < BLOCK_SIZE_BYTES; i++) {
            decrypted_buffer[i] ^= previous_block[i];
        }

        memcpy(previous_block, temp_block, BLOCK_SIZE_BYTES);

        fwrite(decrypted_buffer, 1, BLOCK_SIZE_BYTES, output_file);
    }
    return last_block_size;
}
size_t decrypt_file_CFB(FILE *input_file, FILE *output_file, const uint8_t *key, const size_t key_size, const uint8_t *iv) {
    uint8_t shift_register[BLOCK_SIZE_BYTES];
    uint8_t keystream[BLOCK_SIZE_BYTES];
    uint8_t buffer[BLOCK_SIZE_BYTES];
    uint8_t plaintext[BLOCK_SIZE_BYTES];
    size_t bytes_read;

    // Initialize the shift register with the IV
    memcpy(shift_register, iv, BLOCK_SIZE_BYTES);

    while ((bytes_read = fread(buffer, 1, BLOCK_SIZE_BYTES, input_file)) > 0) {
        // Encrypt the current shift register to produce the keystream
        state_t state;
        stringToState((char *)shift_register, state);
        Cipher(state, key, key_size);
        stateToString(state, (char *)keystream);

        // XOR the ciphertext with the keystream to produce the plaintext segment
        for (size_t i = 0; i < bytes_read; i++) {
            plaintext[i] = buffer[i] ^ keystream[i];
        }

        // Write the plaintext to the output file
        fwrite(plaintext, 1, bytes_read, output_file);

        // Update the shift register with the ciphertext segment
        memcpy(shift_register, buffer, bytes_read);
    }
    return 0;
}
#pragma endregion
#pragma region ---------- Internal AES Core Functions ----------
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
    int round_keys_size = BLOCK_SIZE_BYTES * (Nr + 1);
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
        AddRoundKey(state, &round_keys[round * BLOCK_SIZE_BYTES]);
        // printf("\033[0;35m");
        // printf("round number %d:\n", round+1);
        // printf("\033[0m");
        // print_state(state);
    }
    // Final Round
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, &round_keys[Nr * BLOCK_SIZE_BYTES]);
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
void MixColumns(state_t state) {
    uint8_t col[4];
    for (int col_idx = 0; col_idx < 4; col_idx++) {
        // Extract column
        for (int row = 0; row < 4; row++) {
            col[row] = state[row][col_idx];
        }

        // Mix column
        mix_single_column(col, mix_matrix);

        // Write back column
        for (int row = 0; row < 4; row++) {
            state[row][col_idx] = col[row];
        }
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
//Inverse functions:
void InvCipher(state_t state, const uint8_t *key, size_t key_size) {
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
        //TODO add actual errors
        printf("Invalid key size.\n");
        return;
    }
    int round_keys_size = BLOCK_SIZE_BYTES * (Nr + 1);
    uint8_t *round_keys = (uint8_t *)calloc(round_keys_size, sizeof(uint8_t));

    if (round_keys == NULL) {
        //TODO add actual errors
        printf("Memory allocation failed.\n");
        return;
    }
    KeyExpansion(key, round_keys, key_size);
    AddRoundKey(state, &round_keys[Nr * BLOCK_SIZE_BYTES]); //last round key

    // Main Rounds
    for (int round = Nr -1; round > 0; round--) {  //reserve order of round
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, &round_keys[round * BLOCK_SIZE_BYTES]);
        InvMixColumns(state);
    }
    // Final Round
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, &round_keys[0]);
    free(round_keys);
}
void InvSubBytes(state_t state) {
    for (int col = 0; col < 4; col++) {
        for (int row = 0; row < 4; row++) {
            state[row][col] = inv_sbox[state[row][col]];
        }
    }
}
void InvShiftRows(state_t state) {
    uint8_t temp[4];
    // Row 1 (shift right by 1)
    for (int col = 0; col < 4; col++) {
        temp[col] = state[1][(col - 1 + 4) % 4];
    }
    for (int col = 0; col < 4; col++) {
        state[1][col] = temp[col];
    }

    // Row 2 (shift right by 2)
    for (int col = 0; col < 4; col++) {
        temp[col] = state[2][(col - 2 + 4) % 4];
    }
    for (int col = 0; col < 4; col++) {
        state[2][col] = temp[col];
    }

    // Row 3 (shift right by 3)
    for (int col = 0; col < 4; col++) {
        temp[col] = state[3][(col - 3 + 4) % 4];
    }
    for (int col = 0; col < 4; col++) {
        state[3][col] = temp[col];
    }
}
void InvMixColumns(state_t state) {
    uint8_t col[4];
    for (int col_idx = 0; col_idx < 4; col_idx++) {
        // Extract column
        for (int row = 0; row < 4; row++) {
            col[row] = state[row][col_idx];
        }

        // Mix column using the inverse matrix
        mix_single_column(col, inv_mix_matrix);

        // Write back column
        for (int row = 0; row < 4; row++) {
            state[row][col_idx] = col[row];
        }
    }
}
#pragma endregion
#pragma region ---------- Internal AES Utilities Functions ----------
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
void mix_single_column(uint8_t* col, const uint8_t matrix[4][4]) {
    uint8_t temp[4];
    for (int i = 0; i < 4; i++) {
        temp[i] = gf_multiply(matrix[i][0], col[0]) ^
                  gf_multiply(matrix[i][1], col[1]) ^
                  gf_multiply(matrix[i][2], col[2]) ^
                  gf_multiply(matrix[i][3], col[3]);
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
#pragma endregion
#pragma region ---------- Utilities Functions ----------
// ------------- Utilities Functions -------------
void hex_line_to_state(const char *hex_line, state_t state) {
    // Temporary buffer for storing parsed bytes
    uint8_t temp[BLOCK_SIZE_BYTES];
    int byte_count = 0;

    // Parse the input hex line
    const char *pos = hex_line;
    while (*pos && byte_count < BLOCK_SIZE_BYTES) {
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
void stringToState(const char *input, state_t state) {
    for (int col = 0; col < 4; col++) {
        for (int row = 0; row < 4; row++) {
            state[row][col] = (uint8_t)input[col * 4 + row];
        }
    }
}
void stateToString(const state_t state, char *output) {
    for (int col = 0; col < 4; col++) {
        for (int row = 0; row < 4; row++) {
            output[col * 4 + row] = (char)state[row][col];
        }
    }
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
void add_pkcs7_padding(const char *input, size_t input_len, char *output, size_t *padded_len) {
    size_t padding_len = BLOCK_SIZE_BYTES - (input_len % BLOCK_SIZE_BYTES);
    memcpy(output, input, input_len);
    memset(output + input_len, (uint8_t)padding_len, padding_len); // PKCS#7 padding
    *padded_len = input_len + padding_len;
}
void remove_pkcs7_padding(char *input, int input_len, size_t *unpadded_len) {
    *unpadded_len = 0;
    if (unpadded_len == NULL) {
        //TODO add actual error
        printf("Error: unpadded_len pointer is NULL.\n");
        return;
    }
    if (input_len <= 0 || input_len % BLOCK_SIZE_BYTES != 0) {
        //TODO add actual error
        printf("Error: Input length is invalid.\n");
        return;
    }
    // Get the padding value from the last byte
    uint8_t padding_value = input[input_len - 1];
    
    if (padding_value <= 0 || padding_value > BLOCK_SIZE_BYTES) {
        printf("Error: Invalid padding detected.\n");
        return;
    }

    // Check all padding bytes
    for (int i = 0; i < padding_value - 1; i++) {
        if ((uint8_t)input[input_len - 1 - i] != padding_value) {
            //TODO add error Padding bytes do not match expected value
            return;
        }
    }
    // Calculate the new unpadded length and null-terminate the input
    *unpadded_len = input_len - padding_value;
    input[*unpadded_len] = '\0';
    return;
}
void xor_state_state(state_t state_primary, const state_t state) {
    for (size_t i = 0; i < state_col_len; i++) {
        for (size_t j = 0; j < state_row_len; j++) {
            state_primary[i][j] ^= state[i][j];
        }
    }
}

int get_random_bytes(uint8_t *buffer, size_t length) {
    #ifdef _WIN32
        HCRYPTPROV hProv = 0;
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            printf("Error: CryptAcquireContext failed.\n");
            return 0;
        }
        if (!CryptGenRandom(hProv, (DWORD)length, buffer)) {
            printf("Error: CryptGenRandom failed.\n");
            CryptReleaseContext(hProv, 0);
            return 0;
        }
        CryptReleaseContext(hProv, 0);
        return 1;
    #else
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) {
            perror("Error opening /dev/urandom");
            return 0;
        }
        ssize_t read_bytes = read(fd, buffer, length);
        close(fd);
        if (read_bytes != (ssize_t)length) {
            printf("Error: Did not read required number of bytes.\n");
            return 0;
        }
        return 1;
    #endif
}

#pragma endregion