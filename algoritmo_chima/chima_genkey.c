/**
 * @file genkey.c
 * @author 
 * @brief Funções para geração de chaves pseudoaleatórias.
 * @version 
 * @date 2025-06-13
 * 
 * @copyright Copyright (c) 2025
 * 
 */


// INCLUSÕES //


#include "chima_genkey.h"
#include "utils.h"


// VARIÁVEIS GLOBAIS //

static float lastIteration = 0.0;

// FUNÇÕES //

/**
 * @brief Obtém o valor da última iteração calculada
 *
 * @return float Valor da última iteração

float getLastIteration(void) {
	return lastIteration;
}

/**
 * @brief Define o valor da última iteração calculada
 *
 * @param last Novo valor

void setLastIteration(float last) {
	lastIteration = last;
}

/**
 * @brief Gera os últimos N valores do mapa logístico, descartando os primeiros.
 * 
 * @param totalIter Número total de iterações
 * @param lastValues Vetor de saída para os últimos STORE_COUNT valores
 * @param r Parâmetro do mapa logístico (ex.: 3.99f)
 * @param x0 valor inicial do mapa (0 < x0 < 1)
 */
static void GenerateLogisticMapLastN(float *lastValues, uint32_t totalIter, float r, float x0) {
    float x = x0;
    uint32_t start = (totalIter > STORE_COUNT) ? totalIter - STORE_COUNT : 0;
    uint32_t idx = 0;

    for (uint32_t i = 0; i < totalIter; i++) {
        x = r * x * (1.0f - x);
        if (i >= start) {
            lastValues[idx++] = x;
        }
    }
}

/**
 * @brief Gera uma chave de 128 bits a partir do mapa logístico.
 *
 * @param totalIter Número total de iterações
 * @param r        Parâmetro do mapa logístico
 * @param x0       Valor inicial
 * @param pOutKey  Estrutura para armazenar a chave gerada
 */
void GenerateKey128(uint32_t totalIter, float r, float x0, FloatArray128 *pOutKey) {
    int posA, posB;
    Float32Union uA, uB;
    uint16_t partA, partB;
    uint32_t combined, mixed;
	uint8_t *out;

	float afIterations[STORE_COUNT] = {0};
	GenerateLogisticMapLastN(afIterations, totalIter, r, x0);

    for (uint32_t i = 0; i < 16; i++) {
        pOutKey->bytes[i] = 0;
    }

    for (uint32_t blk = 0; blk < NUM_BLOCKS; blk++) {
        posA = STORE_COUNT - 1 - (2 * blk);
        posB = STORE_COUNT - 1 - (2 * blk + 1);

        uA.f = afIterations[posA];
        uB.f = afIterations[posB];

        partA = uA.parts.low;
        partB = uB.parts.low;

        combined = ((uint32_t)partA << 16) | partB;
        mixed = AVALANCHE(combined);

        out = &pOutKey->bytes[blk * 4];
        out[0] = (mixed >> 24) & 0xFF;
        out[1] = (mixed >> 16) & 0xFF;
        out[2] = (mixed >> 8)  & 0xFF;
        out[3] = (mixed)       & 0xFF;
    }
}
