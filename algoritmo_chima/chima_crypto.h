/**
 * @file cryptography.h
 * @author 
 * @brief Interface para as rotinas criptográficas do CHIMA.
 * @version 
 * @date 2025-06-13
 * 
 * @copyright Copyright (c) 2025
 * 
 */

#ifndef CRYPTOGRAPHY_H
#define CRYPTOGRAPHY_H

// INCLUSÕES //

#include "utils.h"

// DEFINIÇÕES //

/**
 * @brief Define função de rotação de palavras binárias
 * @param buf Variável de uso temporário
 * @param w0 Primeiro valor de entrada
 * @param w1 Segundo valor de entrada
 * @param w2 Terceiro valor de entrada
 * @param w3 Quarto valor de entrada
 * @return Valores trocados
 */
#define ROTWORD(buf, w0, w1, w2, w3) (buf = w0, w0 = w1, w1 = w2, w2 = w3, w3 = buf)

/**
 * @brief Define função de substituição S-BOX
 * @param w0 Primeiro valor de entrada
 * @param w1 Segundo valor de entrada
 * @param w2 Terceiro valor de entrada
 * @param w3 Quarto valor de entrada
 * @return Valores substituídos pela S-BOX
 */
#define SUBWORD(w0, w1, w2, w3) (w0 = g_AesSBox[w0], w1 = g_AesSBox[w1], w2 = g_AesSBox[w2], w3 = g_AesSBox[w3])

// PROTÓTIPOS DE FUNÇÃO //

void AESKeyExpansion(const uint8_t *key, uint8_t *expandedKeys);
uint64_t ApplySBoxAES(uint64_t x, int num_bytes);
uint64_t PermuteWithMask(uint64_t data, uint64_t mask, int num_bits);


void FeistelEncrypt(uint32_t *pBlock, const uint32_t *pRoundKeys32, BlockCipherSize mode);
void FeistelDecrypt(uint32_t *pBlock, const uint32_t *pRoundKeys32, BlockCipherSize mode);


/**
 * @brief Cifra um bloco de dados.
 */
void CHIMA_Cipher(const uint8_t *pt, const uint8_t *key, const uint8_t *iv,
     uint8_t *ciphertext, BlockCipherSize xSize, CipherMode xMode, uint32_t ui32NumRounds);

/**
 * @brief Decifra um bloco previamente cifrado.
 */
void CHIMA_Decipher(const uint8_t *ciphertext, const uint8_t *key, const uint8_t *iv,
     uint8_t *decrypted, BlockCipherSize xSize, CipherMode xMode, uint32_t ui32NumRounds);


/**
 * @brief Define o número de rodadas do Feistel.
 */
void CHIMA_setNumberOfRounds(uint8_t ui8Set);


void CHIMA_EncryptECB(const uint8_t *plaintext, const uint8_t *key,
                uint8_t *ciphertext, BlockCipherSize mode);
void CHIMA_DecryptECB(const uint8_t *ciphertext, const uint8_t *key,
                uint8_t *plaintext, BlockCipherSize mode);

void CHIMA_EncryptCBC(const uint8_t *plaintext,  const uint8_t *key, const uint8_t *iv,
                uint8_t *ciphertext, BlockCipherSize mode);
void CHIMA_DecryptCBC(const uint8_t *ciphertext, const uint8_t *key, const uint8_t *iv,
                uint8_t *plaintext, BlockCipherSize mode);

void CHIMA_EncryptCFB(const uint8_t *plaintext,  const uint8_t *key, const uint8_t *iv,
                uint8_t *ciphertext, BlockCipherSize mode);
void CHIMA_DecryptCFB(const uint8_t *ciphertext, const uint8_t *key, const uint8_t *iv,
                uint8_t *plaintext, BlockCipherSize mode);

void CHIMA_EncryptOFB(const uint8_t *plaintext,  const uint8_t *key, const uint8_t *iv,
                uint8_t *ciphertext, BlockCipherSize mode);
void CHIMA_DecryptOFB(const uint8_t *ciphertext, const uint8_t *key, const uint8_t *iv,
                uint8_t *plaintext, BlockCipherSize mode);

void CHIMA_EncryptCTR(const uint8_t *plaintext,  const uint8_t *key, const uint8_t *iv,
                uint8_t *ciphertext, BlockCipherSize mode);
void CHIMA_DecryptCTR(const uint8_t *ciphertext, const uint8_t *key, const uint8_t *iv,
                uint8_t *plaintext, BlockCipherSize mode);


#endif /* CRYPTOGRAPHY_H */
