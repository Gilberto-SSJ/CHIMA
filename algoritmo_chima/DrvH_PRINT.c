/**
 * @file DrvH_PRINT.c
 * @author Tobias Klein
 * @brief Implementação de um driver simples de I/O para testes.
 * @version 
 * @date 2025-06-13
 * 
 * @copyright Copyright (c) 2025
 * 
 */

#include "DrvH_PRINT.h"
#include <string.h>
#include <stdio.h>

// GLOBAL VARIABLES //

// Ponteiro global para a estrutura
static xLowDriverStackPRINT_t *xLowDriverStackPRINTLocal;

static char cBuffer[256] = {0};

// FUNCTIONS //

/**
  * @brief 	Initializes Low Drivers and Get PRINT Handler Struct
  * @param	xLowDriverStackPRINT_t *xLowDriverStackPRINT :
  * @param	void *vPRINTX_Handle :
  * @retval void
  */
void Init_Low_Drivers_Stack_PRINT(xLowDriverStackPRINT_t *xLowDriverStackPRINT)
{
    xLowDriverStackPRINTLocal = xLowDriverStackPRINT;
}


/**
  * @brief 		  Reads a string from the console until 'Enter' or 32 characters are read
  * @param[out] char *pcString : 
  * @retval 	  uint16_t ui16DataSize
  */
int PRINT_ReadConsole(char *pcString)
{
  if (xLowDriverStackPRINTLocal->pPRINT_Write && xLowDriverStackPRINTLocal->pPRINT_Read)
  {
    int iDataSize = 0;

    while(*pcString != '\r')
    {
      xLowDriverStackPRINTLocal->pPRINT_Read (pcString, 1);
      xLowDriverStackPRINTLocal->pPRINT_Write(pcString, 1);

      if(*pcString == '\r')
        break;

      if(*pcString == '\177')
      {
        *pcString = '\0';
        pcString -= 2;
        iDataSize -= 2;
      }
      pcString ++;
      iDataSize ++;

      if(iDataSize < 0)
    	  iDataSize = 0;
    }
    *pcString = 0;
    return iDataSize;
  }
  return -1;
}

/**
  * @brief 		  Writes a string to the console 
  * @param[out] char *pcString : 
  * @retval 	  uint16_t ui16DataSize
  */
void PRINT_Write(char *pcString, uint16_t ui16DataSize)
{
  if (xLowDriverStackPRINTLocal->pPRINT_Write)
  {
    uint32_t ui16BufferSize = 0;
    ui16BufferSize = (uint32_t) strlen(pcString);

    if ((ui16DataSize == ui16BufferSize) ||
    	  (ui16DataSize == ui16BufferSize-1))
      xLowDriverStackPRINTLocal->pPRINT_Write(pcString, ui16BufferSize);
    else
    {
      for(uint32_t i = 0; i < ui16DataSize; i++)
      {
    	  cBuffer[i] = *pcString;
        pcString++;
      }
      xLowDriverStackPRINTLocal->pPRINT_Write(cBuffer, ui16DataSize);
    }
  }
}
