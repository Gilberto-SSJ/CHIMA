/**
 * @file cryptography.c
 * @author 
 * @brief Implementação das rotinas criptográficas do CHIMA.
 * @version 
 * @date 2025-06-12
 * 
 * @copyright Copyright (c) 2025
 * 
 */


// INCLUSÕES //

#include "chima_crypto.h"
#include "utils.h"


// VARIÁVEIS GLOBAIS //

static uint8_t g_num_rodadas_feistel = 22;

// FUNÇÕES //

/**
 * @brief Define o número de rodadas da rede Feistel
 *
 * @param ui8Set Quantidade de rodadas
 */
void CHIMA_setNumberOfRounds(uint8_t ui8Set) {
	g_num_rodadas_feistel = ui8Set;
}

/**
 * @brief Expande a chave AES de 128 bits para 176 bytes.
 *
 * @param key          Chave original
 * @param expandedKeys Buffer de saída
 */
void AESKeyExpansion(const uint8_t *key, uint8_t *expandedKeys) {
    memcpy(expandedKeys, key, 16);
    uint32_t bytesGenerated = 16;
    uint32_t rconIteration = 1;
    uint8_t temp[4], tempBuf;

    while (bytesGenerated < 176) {
        for (uint32_t i = 0; i < 4; i++)
            temp[i] = expandedKeys[bytesGenerated - 4 + i];

        if (bytesGenerated % 16 == 0) {
            ROTWORD(tempBuf, temp[0], temp[1], temp[2], temp[3]);
        	SUBWORD(temp[0], temp[1], temp[2], temp[3]);
            temp[0] ^= g_AesRcon[rconIteration++];
        }

        for (uint32_t i = 0; i < 4; i++) {
            expandedKeys[bytesGenerated] = expandedKeys[bytesGenerated - 16] ^ temp[i];
            bytesGenerated++;
        }
    }
}

/**
 * @brief Aplica a S-Box AES em cada byte de um valor.
 *
 * @param x         Valor de entrada
 * @param num_bytes Número de bytes válidos
 * @return Valor após substituição
 */
uint64_t ApplySBoxAES(uint64_t x, int num_bytes) {
    uint64_t result = 0;
    uint8_t byte;
    uint8_t sbox_val;
    for (uint32_t i = 0; i < num_bytes; i++) {
        byte = (x >> (8 * i)) & 0xFF;
        sbox_val = g_AesSBox[byte];
        result |= ((uint64_t)sbox_val) << (8 * i);
    }
    return result;
}

/**
 * @brief Permuta bits de acordo com máscara fornecida.
 *
 * @param data     Valor original
 * @param mask     Máscara de permutação
 * @param num_bits Número de bits válidos
 * @return Valor permutado
 */
uint64_t PermuteWithMask(uint64_t data, uint64_t mask, int num_bits) {
    uint64_t result = 0;
    int i = 0, j = num_bits - 1;

    for (uint32_t k = 0; k < num_bits; k++) {
        if ((mask >> k) & 1) {
            result |= ((data >> j) & 1ULL) << k;
            j--;
        } else {
            result |= ((data >> i) & 1ULL) << k;
            i++;
        }
    }
    return result;
}

/**
 * @brief Função de cifragem baseada em rede Feistel.
 *
 * @param block     Bloco de entrada/saída
 * @param roundKeys Chaves de rodada
 * @param mode      Tamanho do bloco
 */
void FeistelEncrypt(uint32_t *block, const uint32_t *roundKeys, BlockCipherSize mode) {
    if (mode == BLOCK_MODE_64) {
        uint32_t L = block[0], R = block[1];
        uint32_t K1, K2;
		uint32_t temp;
        uint32_t sbox;
        for (uint32_t i = 0; i < g_num_rodadas_feistel; i++) {
            K1 = roundKeys[2 * i];
            K2 = roundKeys[2 * i + 1];
            temp = R;
            sbox = ApplySBoxAES(R ^ K1, 4);
            R = L ^ PermuteWithMask(sbox, K2, 32);
            L = temp;
        }
        block[0] = L;
        block[1] = R;
    } else {
        uint32_t L0 = block[0], L1 = block[1], R0 = block[2], R1 = block[3];
        uint64_t R, K, S, P;
        uint32_t temp0, temp1;
        for (uint32_t i = 0; i < g_num_rodadas_feistel; i++) {
            R = ((uint64_t)R0 << 32) | R1;
            K = ((uint64_t)roundKeys[2 * i] << 32) | roundKeys[2 * i + 1];
            S = ApplySBoxAES(R ^ K, 8);
            P = PermuteWithMask(S, K, 64);
            temp0 = R0;
            temp1 = R1;
            R0 = L0 ^ (uint32_t)(P >> 32);
            R1 = L1 ^ (uint32_t)(P & 0xFFFFFFFF);
            L0 = temp0;
            L1 = temp1;
        }
        block[0] = L0; block[1] = L1;
        block[2] = R0; block[3] = R1;
    }
}

/**
 * @brief Processo inverso da rede Feistel para decifração.
 *
 * @param block     Bloco a decifrar
 * @param roundKeys Chaves de rodada
 * @param mode      Tamanho do bloco
 */
void FeistelDecrypt(uint32_t *block, const uint32_t *roundKeys, BlockCipherSize mode) {
    if (mode == BLOCK_MODE_64) {
        uint32_t L = block[0], R = block[1];
        uint32_t K1, K2;
		uint32_t temp;
        uint32_t sbox;
        for (int32_t i = g_num_rodadas_feistel - 1; i >= 0; --i) {
            K1 = roundKeys[2 * i];
            K2 = roundKeys[2 * i + 1];
            temp = L;
            sbox = ApplySBoxAES(L ^ K1, 4);
            L = R ^ PermuteWithMask(sbox, K2, 32);
            R = temp;
        }
        block[0] = L;
        block[1] = R;
    } else {
        uint32_t L0 = block[0], L1 = block[1], R0 = block[2], R1 = block[3];
        uint64_t R, K, S, P;
        uint32_t temp0, temp1;
        for (int32_t i = g_num_rodadas_feistel - 1; i >= 0; --i) {
            R = ((uint64_t)L0 << 32) | L1;
            K = ((uint64_t)roundKeys[2 * i] << 32) | roundKeys[2 * i + 1];
            S = ApplySBoxAES(R ^ K, 8);
            P = PermuteWithMask(S, K, 64);
            temp0 = R0;
            temp1 = R1;
            R0 = L0;
            R1 = L1;
            L0 = temp0 ^ (uint32_t)(P >> 32);
            L1 = temp1 ^ (uint32_t)(P & 0xFFFFFFFF);
        }
        block[0] = L0; block[1] = L1;
        block[2] = R0; block[3] = R1;
    }
}

/**
 * @brief Interface genérica para cifrar blocos
 * 
 * @param pt 
 * @param key 
 * @param iv 
 * @param ct 
 * @param xSize 
 * @param xMode
 * @param ui32NumRounds 
 */
void CHIMA_Cipher(const uint8_t *plaintext, const uint8_t *key, const uint8_t *iv,
     uint8_t *ciphertext, BlockCipherSize xSize, CipherMode xMode, uint32_t ui32NumRounds) {

    // Atualiza o número de rodadas se possível
    if (ui32NumRounds >= 9 && ui32NumRounds <= 22) {
        CHIMA_setNumberOfRounds(ui32NumRounds);
    } else PRINT_Write("Número de rodadas inválido. Usando última configuração.\n", 53);

    switch (xMode) {
        case CIPHER_MODE_ECB: CHIMA_EncryptECB(plaintext, key,     ciphertext, xSize); break;
        case CIPHER_MODE_CBC: CHIMA_EncryptCBC(plaintext, key, iv, ciphertext, xSize); break;
        case CIPHER_MODE_CFB: CHIMA_EncryptCFB(plaintext, key, iv, ciphertext, xSize); break;
        case CIPHER_MODE_OFB: CHIMA_EncryptOFB(plaintext, key, iv, ciphertext, xSize); break;
        case CIPHER_MODE_CTR: CHIMA_EncryptCTR(plaintext, key, iv, ciphertext, xSize); break;
    }
}

/**
 * @brief Interface genérica para decifrar blocos
 * 
 * @param ct 
 * @param key 
 * @param iv 
 * @param pt 
 * @param xSize 
 * @param xMode
 * @param ui32NumRounds
 */
void CHIMA_Decipher(const uint8_t *ciphertext, const uint8_t *key, const uint8_t *iv,
     uint8_t *decrypted, BlockCipherSize xSize, CipherMode xMode, uint32_t ui32NumRounds) {

    // Atualiza o número de rodadas se possível
    if (ui32NumRounds >= 9 && ui32NumRounds <= 22) {
        CHIMA_setNumberOfRounds(ui32NumRounds);
    } else PRINT_Write("Número de rodadas inválido. Usando última configuração.\n", 53);

    switch (xMode) {
        case CIPHER_MODE_ECB: CHIMA_DecryptECB(ciphertext, key,     decrypted, xSize); break;
        case CIPHER_MODE_CBC: CHIMA_DecryptCBC(ciphertext, key, iv, decrypted, xSize); break;
        case CIPHER_MODE_CFB: CHIMA_DecryptCFB(ciphertext, key, iv, decrypted, xSize); break;
        case CIPHER_MODE_OFB: CHIMA_DecryptOFB(ciphertext, key, iv, decrypted, xSize); break;
        case CIPHER_MODE_CTR: CHIMA_DecryptCTR(ciphertext, key, iv, decrypted, xSize); break;
    }
}


// MODO DE CIFRA //

/**
 * @brief Expande a chave mestra em chaves de rodada de 32 bits.
 *
 * @param key         Chave de 128 bits
 * @param roundKeys32 Vetor de saída
 */
static void Expand_Round_Keys(const uint8_t *key, uint32_t *roundKeys32) {
    uint8_t expandedKey[176] = {0};
    AESKeyExpansion(key, expandedKey);

    for (uint32_t k = 0; k < 44; k++) {
        roundKeys32[k] = ((uint32_t)expandedKey[k * 4]     << 24) |
                         ((uint32_t)expandedKey[k * 4 + 1] << 16) |
                         ((uint32_t)expandedKey[k * 4 + 2] << 8)  |
                         ((uint32_t)expandedKey[k * 4 + 3]);
    }
}

/**
 * @brief Cifra um único bloco.
 *
 * @param input  Dados de entrada
 * @param rk     Chaves expandidas
 * @param output Buffer de saída
 * @param mode   Tamanho do bloco
 */
static void Block_Encrypt(const uint8_t *input, const uint32_t *rk, uint8_t *output, BlockCipherSize mode) {
    uint32_t block[4] = {0};
    BlockFromBytes(input, block, mode);
    FeistelEncrypt(block, rk, mode);
    BlockToBytes(block, output, mode);
}

/**
 * @brief Decifra um único bloco.
 *
 * @param input  Dados cifrados
 * @param rk     Chaves expandidas
 * @param output Buffer de saída
 * @param mode   Tamanho do bloco
 */
static void Block_Decrypt(const uint8_t *input, const uint32_t *rk, uint8_t *output, BlockCipherSize mode) {
    uint32_t block[4] = {0};
    BlockFromBytes(input, block, mode);
    FeistelDecrypt(block, rk, mode);
    BlockToBytes(block, output, mode);
}

/**
 * @brief Copia bytes para um buffer auxiliar.
 *
 * @param src Fonte
 * @param dst Destino
 * @param len Quantidade de bytes
 */
static void Load_Block(const uint8_t *src, uint8_t *dst, uint32_t len) {
    for (uint32_t i = 0; i < len; i++)
    	dst[i] = src[i];
}

// OPERATION MODES //

/**
 * @brief Modo ECB - Encrypt
 *
 * @param plaintext
 * @param key
 * @param ciphertext
 * @param mode
 */
void CHIMA_EncryptECB(const uint8_t *plaintext, const uint8_t *key, uint8_t *ciphertext, BlockCipherSize mode) {
    uint32_t rk[44];
    Expand_Round_Keys(key, rk);
    Block_Encrypt(plaintext, rk, ciphertext, mode);
}

/**
 * @brief Modo ECB - Decrypt
 *
 * @param ciphertext
 * @param key
 * @param plaintext
 * @param mode
 */
void CHIMA_DecryptECB(const uint8_t *ciphertext, const uint8_t *key, uint8_t *plaintext, BlockCipherSize mode) {
    uint32_t rk[44];
    Expand_Round_Keys(key, rk);
    Block_Decrypt(ciphertext, rk, plaintext, mode);
}

/**
 * @brief Modo CBC - Encrypt
 *
 * @param pt
 * @param key
 * @param iv
 * @param ct
 * @param mode
 */
void CHIMA_EncryptCBC(const uint8_t *pt, const uint8_t *key, const uint8_t *iv, uint8_t *ct, BlockCipherSize mode) {
	uint32_t bs = (mode == BLOCK_MODE_64) ? 8 : 16;
    uint8_t iv_local[16] = {0}, xor_buf[16] = {0};

    Load_Block(iv, iv_local, bs);
    XOR_Blocks(xor_buf, pt, iv_local, bs);

    uint32_t rk[44] = {0};
    Expand_Round_Keys(key, rk);
    Block_Encrypt(xor_buf, rk, ct, mode);
}

/**
 * @brief Modo CBC - Decrypt
 *
 * @param ct
 * @param key
 * @param iv
 * @param pt
 * @param mode
 */
void CHIMA_DecryptCBC(const uint8_t *ct, const uint8_t *key, const uint8_t *iv, uint8_t *pt, BlockCipherSize mode) {
	uint32_t bs = (mode == BLOCK_MODE_64) ? 8 : 16;
    uint8_t iv_local[16] = {0}, temp[16] = {0};

    Load_Block(iv, iv_local, bs);

    uint32_t rk[44] = {0};
    Expand_Round_Keys(key, rk);
    Block_Decrypt(ct, rk, temp, mode);
    XOR_Blocks(pt, temp, iv_local, bs);
}

/**
 * @brief Modo CFB - Encrypt
 *
 * @param pt
 * @param key
 * @param iv
 * @param ct
 * @param mode
 */
void CHIMA_EncryptCFB(const uint8_t *pt, const uint8_t *key, const uint8_t *iv, uint8_t *ct, BlockCipherSize mode) {
	uint32_t bs = (mode == BLOCK_MODE_64) ? 8 : 16;
    uint8_t feedback[16] = {0}, stream[16] = {0};

    Load_Block(iv, feedback, bs);

    uint32_t rk[44];
    Expand_Round_Keys(key, rk);
    Block_Encrypt(feedback, rk, stream, mode);
    XOR_Blocks(ct, pt, stream, bs);
}

/**
 * @brief Modo CFB - Decrypt
 *
 * @param ct
 * @param key
 * @param iv
 * @param pt
 * @param mode
 */
void CHIMA_DecryptCFB(const uint8_t *ct, const uint8_t *key, const uint8_t *iv, uint8_t *pt, BlockCipherSize mode) {
    CHIMA_EncryptCFB(ct, key, iv, pt, mode);
}

/**
 * @brief Modo OFB - Encrypt
 *
 * @param pt
 * @param key
 * @param iv
 * @param ct
 * @param mode
 */
void CHIMA_EncryptOFB(const uint8_t *pt, const uint8_t *key, const uint8_t *iv, uint8_t *ct, BlockCipherSize mode) {
	uint32_t bs = (mode == BLOCK_MODE_64) ? 8 : 16;
    uint8_t stream[16] = {0}, output_block[16] = {0};

    Load_Block(iv, output_block, bs);

    uint32_t rk[44];
    Expand_Round_Keys(key, rk);
    Block_Encrypt(output_block, rk, stream, mode);
    XOR_Blocks(ct, pt, stream, bs);
}

/**
 * @brief Modo OFB - Decrypt
 *
 * @param ct
 * @param key
 * @param iv
 * @param pt
 * @param mode
 */
void CHIMA_DecryptOFB(const uint8_t *ct, const uint8_t *key, const uint8_t *iv, uint8_t *pt, BlockCipherSize mode) {
    CHIMA_EncryptOFB(ct, key, iv, pt, mode);
}

/**
 * @brief Modo CTR - Encrypt
 *
 * @param pt
 * @param key
 * @param iv
 * @param ct
 * @param mode
 */
void CHIMA_EncryptCTR(const uint8_t *pt, const uint8_t *key, const uint8_t *iv, uint8_t *ct, BlockCipherSize mode) {
	uint32_t bs = (mode == BLOCK_MODE_64) ? 8 : 16;
    uint8_t counter[16] = {0}, stream[16] = {0};

    Load_Block(iv, counter, bs);

    uint32_t rk[44];
    Expand_Round_Keys(key, rk);
    Block_Encrypt(counter, rk, stream, mode);
    XOR_Blocks(ct, pt, stream, bs);
}

/**
 * @brief Modo CTR - Decrypt
 *
 * @param ct
 * @param key
 * @param iv
 * @param pt
 * @param mode
 */
void CHIMA_DecryptCTR(const uint8_t *ct, const uint8_t *key, const uint8_t *iv, uint8_t *pt, BlockCipherSize mode) {
    CHIMA_EncryptCTR(ct, key, iv, pt, mode);
}
