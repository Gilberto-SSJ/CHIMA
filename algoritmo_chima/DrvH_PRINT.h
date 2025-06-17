/**
 * @file DrvH_PRINT.h
 * @author Tobias Klein
 * @brief 
 * @version 
 * @date 2025-06-13
 * 
 * @copyright Copyright (c) 2025
 * 
 */

 
#ifndef DRVH_PRINT_H
#define DRVH_PRINT_H

// INCLUDES //

#include <stdint.h>

// TYPES //


/* Definição de tipo para as funções que o usuario
da stack de crypto vai ter que providenciar em uso */
typedef void (*Function_PRINT_Write) (char *, uint16_t);
typedef void (*Function_PRINT_Read ) (char *, uint16_t);


/* Estrutura de dados contendo o ponteiro para
as funções que o usuario da stack precisa preencher */
typedef struct {
    Function_PRINT_Write pPRINT_Write;
    Function_PRINT_Read  pPRINT_Read;
} xLowDriverStackPRINT_t;

// FUNCTION PROTOTYPES //

/**
 * @brief Inicializa o driver de impressão.
 * @param xLowDriverStackPRINT Estrutura com funções do usuário
 */
void Init_Low_Drivers_Stack_PRINT(xLowDriverStackPRINT_t *xLowDriverStackPRINT);

/**
 * @brief Lê uma string da console.
 * @param pcString Buffer de saída
 * @return Tamanho lido
 */
int  PRINT_ReadConsole(char *pcString);

/**
 * @brief Escreve dados na console.
 * @param pcString Dados a escrever
 * @param ui16DataSize Tamanho em bytes
 */
void PRINT_Write(char *pcString, uint16_t ui16DataSize);


#endif /* DRVH_PRINT_H */
