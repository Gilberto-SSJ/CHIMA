/**
 * @file genkey.h
 * @author 
 * @brief 
 * @version 
 * @date 2025-06-13
 * 
 * @copyright Copyright (c) 2025
 * 
 */

#ifndef GENKEY_H
#define GENKEY_H


// INCLUSÕES //

#include <stdint.h>

// DEFINIÇÕES //

#define STORE_COUNT      64
#define ITER_BUFFER_SIZE 1000
#define NUM_BLOCKS       4  


/**
 * @brief Realiza a operação avalanche para dispersão de bits
 * @param x Valor de entrada (32 bits)
 * @return uint32_t Valor misturado (mais aleatório)
 */
#define AVALANCHE(x) (((x) * 0xD168AAAD) ^ (((x) * 0xD168AAAD) >> 16))


// TIPOS //
/**
 * @brief União para acessar partes de um número de ponto flutuante.
 */
typedef union {
    float f;
    struct {
        uint16_t low;
        uint16_t high;
    } parts;
} Float32Union;


/**
 * @brief Estrutura que armazena 128 bits de chave.
 */
typedef struct {
    uint8_t bytes[16]; 
} FloatArray128;

// PROTÓTIPOS DE FUNÇÃO //

/**
 * @brief Gera uma chave de 128 bits usando mapa logístico.
 *
 * @param totalIter Número total de iterações do mapa
 * @param r         Parâmetro r do mapa logístico
 * @param x0        Valor inicial
 * @param pOutKey   Estrutura para armazenar a chave
 */
void GenerateKey128(uint32_t totalIter, float r, float x0, FloatArray128 *pOutKey);

/**
 * @brief Obtém o último valor calculado no mapa logístico.
 */
float getLastIteration(void);

/**
 * @brief Define o último valor calculado no mapa logístico.
 * @param last Valor a armazenar
 */
void  setLastIteration(float last);


#endif /* GENKEY_H */
