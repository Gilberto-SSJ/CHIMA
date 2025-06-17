/**
 * @file utils.c
 * @author 
 * @brief 
 * @version 
 * @date 2025-06-09
 * 
 * @copyright Copyright (c) 2025
 * 
 */

// INCLUDES //

#include "utils.h"
#include <stdio.h>

// GLOBAL VARIABLES //

// S-Box and Rcon tables for AES
const uint8_t g_AesSBox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

const uint8_t g_AesRcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

// FUNCTIONS //

/* ========================= */
/* === Impressão de Dados === */
/* ========================= */

/**
 * @brief 
 * 
 * @param label 
 * @param block 
 * @param len 
 */
void Print_Block_hex(const char *label, const uint8_t *block, uint32_t len) {
    char cBuffer[32] = {0};
    uint32_t ui32Size = sprintf(cBuffer, "%s: ", label);
    PRINT_Write(cBuffer, ui32Size);
    for (uint32_t i = 0; i < len; i++) {
        ui32Size = sprintf(cBuffer, "%02X", block[i]);
        PRINT_Write(cBuffer, ui32Size);
    }
    PRINT_Write("\n", 2);
}

/**
 * @brief 
 * 
 * @param label 
 * @param block 
 * @param len 
 */
void Print_Block_bin(const char *label, const uint8_t *block, uint32_t len) {
    char cBuffer[32] = {0};
    uint32_t ui32Size = sprintf(cBuffer, "%s: ", label);
    PRINT_Write(cBuffer, ui32Size);
    for (uint32_t i = 0; i < len; i++)
        for (int32_t b = 7; b >= 0; b--) {
            ui32Size = sprintf(cBuffer, "%d", (block[i] >> b) & 1);
            PRINT_Write(cBuffer, ui32Size);
        }
    PRINT_Write("\n", 2);
}


/* =========================== */
/* === Conversões de Block === */
/* =========================== */

/**
 * @brief 
 * 
 * @param input 
 * @param output 
 * @param mode 
 */
void BlockFromBytes(const uint8_t *input, uint32_t *output, BlockCipherSize mode) {
    int words = (mode == BLOCK_MODE_64) ? 2 : 4;
    for (int i = 0; i < words; ++i)
        output[i] = ((uint32_t)input[i * 4 + 0]) |
                    ((uint32_t)input[i * 4 + 1] << 8) |
                    ((uint32_t)input[i * 4 + 2] << 16) |
                    ((uint32_t)input[i * 4 + 3] << 24);
}

/**
 * @brief 
 * 
 * @param input 
 * @param output 
 * @param mode 
 */
void BlockToBytes(const uint32_t *input, uint8_t *output, BlockCipherSize mode) {
    int words = (mode == BLOCK_MODE_64) ? 2 : 4;
    for (int i = 0; i < words; ++i) {
        output[i * 4 + 0] = (uint8_t)(input[i]);
        output[i * 4 + 1] = (uint8_t)(input[i] >> 8);
        output[i * 4 + 2] = (uint8_t)(input[i] >> 16);
        output[i * 4 + 3] = (uint8_t)(input[i] >> 24);
    }
}

/**
 * @brief 
 * 
 * @param input 
 * @param block 
 * @param mode 
 */
void BlockFromStringGeneric(const char *input, uint32_t *block, BlockCipherSize mode) {
    BlockFromBytes((const uint8_t *)input, block, mode);
}

/**
 * @brief 
 * 
 * @param block 
 * @param output 
 * @param mode 
 */
void BlockToStringGeneric(const uint32_t *block, char *output, BlockCipherSize mode) {
    BlockToBytes(block, (uint8_t *)output, mode);
}

/* ========================== */
/* === Conversões Binárias === */
/* ========================== */

/**
 * @brief 
 * 
 * @param key 
 * @param tamanho 
 * @param saida 
 */
void ConverterKeyParaStringBinaria(const uint8_t *key, int tamanho, char *saida) {
    for (int i = 0; i < tamanho; i++)
        for (int b = 7; b >= 0; b--)
            saida[i * 8 + (7 - b)] = ((key[i] >> b) & 1) ? '1' : '0';
    saida[tamanho * 8] = '\0';
}

/**
 * @brief 
 * 
 * @param bin_str 
 * @param bytes 
 * @param len 
 */
void BinStringToBytes(const char *bin_str, uint8_t *bytes, int len) {
    for (int i = 0; i < len; i++) {
        bytes[i] = 0;
        for (int b = 0; b < 8; b++)
            bytes[i] |= (bin_str[i * 8 + b] == '1' ? 1 : 0) << (7 - b);
    }
}

/* ======================== */
/* === Padding e Unpad === */
/* ======================== */

/**
 * @brief 
 * 
 * @param value 
 * @param block 
 * @param modo 
 */
void Padding(float value, uint8_t *block, BlockCipherSize modo) {
    size_t block_size = (modo == BLOCK_MODE_64) ? 8 : 16;
    size_t len_float = sizeof(float);
    uint8_t pad = (uint8_t)(block_size - len_float);

    memcpy(block, &value, len_float);
    memset(block + len_float, pad, pad);
}

/**
 * @brief 
 * 
 * @param block 
 * @param modo 
 * @param value 
 * @return int 
 */
int RemovePadding(const uint8_t *block, BlockCipherSize modo, float *value) {
    uint32_t block_size = (modo == BLOCK_MODE_64) ? 8 : 16;
    uint32_t len_float = sizeof(float);
    uint8_t pad = block[block_size - 1];

    if (pad > block_size - len_float) return -1;

    memcpy(value, block, len_float);
    return 0;
}

/* ========================== */
/* === Operações com XOR ==== */
/* ========================== */

/**
 * @brief 
 * 
 * @param dst 
 * @param a 
 * @param b 
 * @param len 
 */
void XOR_Blocks(uint8_t *dst, const uint8_t *a, const uint8_t *b, uint32_t len) {
    for (uint32_t i = 0; i < len; i++)
        dst[i] = a[i] ^ b[i];
}
