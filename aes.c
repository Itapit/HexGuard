#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "aes.h"
#define block_size_bytes 16
#define state_row_len 4
#define state_col_len 4

void stringToState(const char *input, state_t state){
    if (strlen(input) != block_size_bytes) {
        return;
    }
    for (int i = 0; i < state_row_len; i++) {
        for (int ii = 0; ii < state_col_len; ii++) {
            state[i][ii] = input[i * state_row_len + ii];
        }
    }  
}

void stateToString(const state_t state, char *output){
    if (strlen(output) != block_size_bytes) {
        return;
    }
    for (int i = 0; i < state_row_len; i++){
        for (int ii = 0; ii < state_col_len; ii++){
            output[i * 4 + ii] = state[i][ii];   
        }
    }
}