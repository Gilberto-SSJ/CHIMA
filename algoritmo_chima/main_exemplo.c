/**
 * @file main_exemplo.c
 * @author 
 * @brief Exemplo de uso da biblioteca CHIMA
 * @version 
 * @date 2025-06-13
 * 
 * @copyright Copyright (c) 2025
 * 
 */

// INCLUDES //

#include <stdint.h>
#include <stdio.h>
#include <math.h>

#include "chima_genkey.h"
#include "chima_crypto.h"
#include "autentication.h"
#include "utils.h"

// DEFINES //

// Logistic Map Parameters
#define LOGISTIC_R        3.72f
#define LOGISTIC_X0       0.5f

// Crytography Parameters
#define BLOCK_SIZE        BLOCK_MODE_128
#define OPERATION_MODE    CIPHER_MODE_CBC
#define NUMBER_OF_ROUNDS  22

// FUNCTIONS //

/**
 * @brief Demonstra cifragem, decifragem e autenticação de um valor.
 */
void testar_value(float PLAIN_TEXT, int index) {
    uint8_t plaintext [16] = {0};
    uint8_t ciphertext[16] = {0};
    uint8_t decrypted [16] = {0};
    uint8_t iv [16] = {0};


    // Usuario pode ou não criar a chave com nosso Gerador de Chaves

    FloatArray128 user_key; // Estrutura de 128 bits para armazenar a chave
    GenerateKey128(ITER_BUFFER_SIZE, LOGISTIC_R, LOGISTIC_X0, &user_key); // Função nossa de geração de chave mestra
    // A Chave gerada fica armazenada em user_key


    // Prepara o plaintext para cifragem

    Padding(PLAIN_TEXT, plaintext, BLOCK_SIZE); // Função de Padding nossa em utils.c

    for (int i = 0; i < 16; i++) iv[i] = i; // Neste exemplo, o IV possui um valor diferente de 0.

    // Cifra e decifra o plaintext usando a chave gerada
    CHIMA_Cipher  (plaintext, user_key.bytes, iv, ciphertext, BLOCK_SIZE, OPERATION_MODE, NUMBER_OF_ROUNDS);  // Função de cifragem nossa EM cryptography.c
    CHIMA_Decipher(ciphertext, user_key.bytes, iv, decrypted, BLOCK_SIZE, OPERATION_MODE, NUMBER_OF_ROUNDS); // Função de decifragem nossa EM cryptography.c

    // Remove o padding do texto decifrado

    float result = 0.0f;
    int status = RemovePadding(decrypted, BLOCK_SIZE, &result); // Função de remoção de padding nossa em utils.c

    
    // Exemplo de autenticação //

    uint8_t aucCombinedData[12]; // Buffer para os dados combinados - opção do usuário

    BitSequence aucHashVal[LESAMNTALW_HASH_BITLENGTH / 8] = {0}; // Buffer para a recepção Hash

    // Exemplo de combinação de dados para autenticação // não obrigatório
    memcpy(aucCombinedData, ciphertext, 8);
	float lastIteration = getLastIteration();
	memcpy(aucCombinedData + 8, &lastIteration, sizeof(lastIteration));

	// Uso da Autenticação com Lesamnta-LW //
    
    LesamntaLW_Hash(aucCombinedData, sizeof(aucCombinedData) * 8, aucHashVal); // Função de Hash em autentication.c

    // aucHashVal agora contém o hash dos dados combinados



    // A partir daqui é só print do usuário, a unica coisa nossa mais é a função Print_Block_bin e Print_Block_hex
    // Essas funções estão em utils.c, e são usadas para imprimir os valores binário e hexadecimais através do método que o usuário passou
    // de resto, não documentar


    Print_Block_hex("PLAINTEXT", plaintext, (BLOCK_SIZE == BLOCK_MODE_64) ? 8 : 16);
    Print_Block_bin("PLAINTEXT", plaintext, (BLOCK_SIZE == BLOCK_MODE_64) ? 8 : 16);
    printf("\n");

    Print_Block_hex("KEY", user_key.bytes, 16);
    Print_Block_bin("KEY", user_key.bytes, 16);
    printf("\n");

    if (OPERATION_MODE != CIPHER_MODE_ECB) {
        Print_Block_hex("IV", iv, (BLOCK_SIZE == BLOCK_MODE_64) ? 8 : 16);
        Print_Block_bin("IV", iv, (BLOCK_SIZE == BLOCK_MODE_64) ? 8 : 16);
        printf("\n");
    }

    Print_Block_hex("CIPHERTEXT", ciphertext, (BLOCK_SIZE == BLOCK_MODE_64) ? 8 : 16);
    Print_Block_bin("CIPHERTEXT", ciphertext, (BLOCK_SIZE == BLOCK_MODE_64) ? 8 : 16);
    printf("\n");

    Print_Block_hex("DECIPHERED", decrypted, (BLOCK_SIZE == BLOCK_MODE_64) ? 8 : 16);
    Print_Block_bin("DECIPHERED", decrypted, (BLOCK_SIZE == BLOCK_MODE_64) ? 8 : 16);
    printf("\n");

    printf("VALUE DECIPHERED: %.6f\n", result);

    if (status != 0) {
        printf("[ERRO] Padding inválido!\n");
    } else if (fabsf(PLAIN_TEXT - result) < 0.00001f) {
        printf("[OK] value recuperado com sucesso.\n");
    } else {
        printf("[FALHA] value recuperado incorretamente.\n");
    }

    printf("============================\n\n");
}



/**
 * @brief Função de escrita usada no exemplo.
 */
void User_PRINT_Write(char* serialBuffer, uint16_t size)
{
	printf(serialBuffer);
}


/**
 * @brief Função de leitura usada no exemplo.
 */
void User_PRINT_Read(char* serialBuffer, uint16_t size)
{
    scanf(" %c", serialBuffer);
}


// MAIN //

int main(void) {

    // Inicialização do nosso driver de impressão com funções do usuário
    xLowDriverStackPRINT_t xLowDriverStackPRINT = {
	    xLowDriverStackPRINT.pPRINT_Write = User_PRINT_Write,
	    xLowDriverStackPRINT.pPRINT_Read  = User_PRINT_Read ,
    };

    float tests[] = {
        0.0f,
        -0.0f,
        1.0f,
        -1.0f,
        120.87f,
        123456.78f,
        1.175494e-38f,
        -1.175494e-38f,
        3.402823e+38f,
        -3.402823e+38f
    };

    int total = sizeof(tests) / sizeof(tests[0]);

    for (int i = 0; i < total; i++) {
        testar_value(tests[i], i); // função do usuário de teste da criptografia, não documentar
    }

    return 0;
}
