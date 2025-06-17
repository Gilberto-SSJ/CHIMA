/**
 * @file utils.h
 * @author 
 * @brief Funções auxiliares para criptografia e utilidades diversas.
 * @version 
 * @date 2025-06-13
 * 
 * @copyright Copyright (c) 2025
 * 
 */

#ifndef UTILS_H
#define UTILS_H

// INCLUSÕES //

#include <stdlib.h>
#include <string.h>
#include "DrvH_PRINT.h"

// TIPOS //

/**
 * @brief 
 * 
 */
typedef enum {
    BLOCK_MODE_64,
    BLOCK_MODE_128
} BlockCipherSize;

/**
 * @brief 
 * 
 */
typedef enum {
    CIPHER_MODE_ECB,
    CIPHER_MODE_CBC,
    CIPHER_MODE_CFB,
    CIPHER_MODE_OFB,
    CIPHER_MODE_CTR
} CipherMode;

// VARIÁVEIS GLOBAIS //

extern const uint8_t g_AesSBox[256];
extern const uint8_t g_AesRcon[11];

// PROTÓTIPOS DE FUNÇÃO //

uint8_t *get_iv_buffer(void);

void Print_Block_hex(const char *label, const uint8_t *block, uint32_t len);
void Print_Block_bin(const char *label, const uint8_t *data, uint32_t len);
void BinStringToBytes(const char *bin_str, uint8_t *bytes, int length);

void BlockFromStringGeneric(const char *input, uint32_t *pBlock, BlockCipherSize mode);
void BlockToStringGeneric(const uint32_t *pBlock, char *output, BlockCipherSize mode);
void ConverterKeyParaStringBinaria(const uint8_t *chave, int tamanhoBytes, char *stringBinaria);
void BlockFromBytes(const uint8_t *input, uint32_t *output, BlockCipherSize mode);
void BlockToBytes(const uint32_t *input, uint8_t *output, BlockCipherSize mode);

/**
 * @brief Aplica padding PKCS no valor informado.
 */
void Padding(float value, uint8_t *block, BlockCipherSize modo);

/**
 * @brief Remove o padding de um bloco.
 * @return 0 em caso de sucesso
 */
int RemovePadding(const uint8_t *block, BlockCipherSize modo, float *value);
/**
 * @brief Realiza operação XOR byte a byte.
 */
void XOR_Blocks(uint8_t *dst, const uint8_t *a, const uint8_t *b, uint32_t len);


#endif /* UTILS_H */
