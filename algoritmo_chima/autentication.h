/**
 * @file autentication.h
 * @brief Definições da função de hash Lesamnta-LW.
 */

#ifndef AUTENTICATION_H
#define AUTENTICATION_H

// INCLUSÕES //

#include <stdint.h>

// DEFINIÇÕES //

#define LESAMNTALW_HASH_BITLENGTH 256
#define ENDIAN isBigEndian()

// TIPOS //

/**
 * @brief Códigos de retorno da API de hash.
 */
typedef enum {
    SUCCESS_ = 0,    /**< Operação bem sucedida */
    FAIL = 1,        /**< Falha geral */
    BAD_HASHBITLEN = 2 /**< Tamanho de hash inválido */
} HashReturn;

typedef unsigned char BitSequence;
typedef uint64_t DataLength;

// PROTÓTIPOS DE FUNÇÃO //

/**
 * @brief Calcula o hash Lesamnta-LW.
 *
 * @param pcData       Dados de entrada
 * @param dlDataBitLen Comprimento dos dados em bits
 * @param pcHashVal    Buffer para o valor de hash (256 bits)
 * @return Código de retorno
 */
HashReturn LesamntaLW_Hash(const BitSequence *pcData, DataLength dlDataBitLen, BitSequence *pcHashVal);


#endif /* AUTENTICATION_H */
