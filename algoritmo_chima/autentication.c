/**
 * @file autentication.c
 * @brief Implementação do hash Lesamnta-LW usado para autenticação.
 * @date 27/05/2025
 */

#include "autentication.h"
#include "utils.h"
#include <string.h>

/**
 * @brief União utilizada para facilitar conversões entre palavras e bytes.
 */
typedef union{
	uint32_t ui32;
	struct{
		uint16_t ui16_1;
		uint16_t ui16_0;
	};
	uint16_t ui16[2];
	struct{
		uint8_t ui8_3;
		uint8_t ui8_2;
		uint8_t ui8_1;
		uint8_t ui8_0;
	};
	uint8_t  ui8 [4];
	struct xBitfield{
		uint8_t b7 : 1;
		uint8_t b6 : 1;
		uint8_t b5 : 1;
		uint8_t b4 : 1;
		uint8_t b3 : 1;
		uint8_t b2 : 1;
		uint8_t b1 : 1;
		uint8_t b0 : 1;
	} byte[4];
} uxConverter;

/**
 * @brief Parâmetros do Lesamnta-LW
 * 
 */
enum {
    /* Comprimento do hash */
    HashLengthInBit  = LESAMNTALW_HASH_BITLENGTH,
    HashLengthInByte = LESAMNTALW_HASH_BITLENGTH / 8,
    HashLengthInWord = LESAMNTALW_HASH_BITLENGTH / 32,
    /* Função de compressão */
    MessageBlockLengthInBit  = 128,
    MessageBlockLengthInByte = 128 / 8,
    MessageBlockLengthInWord = 128 / 32,
    /* Parte do bloco cifrador */
    NumberOfRounds = 64,
    KeyLengthInBit  = 128,
    KeyLengthInByte = 128 / 8,
    KeyLengthInWord = 128 / 32,
    BlockLengthInBit  = 256,
    BlockLengthInByte = 256 / 8,
    BlockLengthInWord = 256 / 32,
};

/**
 * @brief Valores iniciais (usados para o hash)
 * 
 */
static const uint32_t ui32InitialValue[8] = {
    0x00000256U, 0x00000256U, 0x00000256U, 0x00000256U,
    0x00000256U, 0x00000256U, 0x00000256U, 0x00000256U,
};

/**
 * @brief Constantes de rodada
 * 
 */
static const uint32_t C[64] = {
    0xa432337fU, 0x945e1f8fU, 0x92539a11U, 0x24b90062U,
    0x6971c64cU, 0xd6e3f449U, 0x2c2f0da9U, 0x33769295U,
    0xeb506df2U, 0x708cebfeU, 0xb83ab7bfU, 0x97df0f17U,
    0x9223b802U, 0x7fa29140U, 0x0ff45228U, 0x01fe8a45U,
    0xed016ee8U, 0x1da02dddU, 0xee8aba1bU, 0x46c4c223U,
    0x53cd0d24U, 0xd1b46d24U, 0xc1fb4124U, 0xc3f2a4a4U,
    0xc3b39814U, 0xc3bbbf82U, 0x759191b0U, 0x0eb23236U,
    0xb7fd6c86U, 0xa0d48750U, 0x141a90eaU, 0x6f65b45dU,
    0xe0d2092bU, 0x470fd445U, 0xe5df4528U, 0x1cbbe8a5U,
    0xeea9c2b4U, 0xc618f4d6U, 0xaee8345aU, 0x783be0cbU,
    0x5412e979U, 0x3c712e0fU, 0x87567c21U, 0x2619bca4U,
    0xdf0efb14U, 0xc02c13e2U, 0x75e3643cU, 0xd571a007U,
    0x9a766de0U, 0x134ecdbcU, 0xd9a41537U, 0x9becdb46U,
    0xa556b1a8U, 0x14aad635U, 0xefabe566U, 0xabde566cU,
    0xceb6064dU, 0xf4e87f69U, 0x286e7ccdU, 0xe8337039U,
    0x2bf51d27U, 0x85a6fa44U, 0xcb7913c8U, 0x196f2279U,
};

/**
 * @brief Verifica se a arquitetura é Big Endian
 *
 * @return uint8_t 1 para Big Endian, 0 para Little Endian
*/
const uint8_t isBigEndian(void){
	volatile uint32_t i = 0x01234567;
	return (*((uint8_t*)(&i))) == 0x01;
}

/**
 * @brief Multiplicação por 2 no campo GF(256).
 *
 * @param ucV Byte de entrada
 * @return Byte resultante
 */
static uint8_t Mul02(uint8_t ucV)
{
    uint16_t uTemp = ucV << 1;
    if (uTemp > 0xff) {
        uTemp = uTemp - 0x100;
        uTemp ^= 0x1b;
    }
    return (uint8_t)uTemp;
}

/**
 * @brief Multiplicação por 3 no campo GF(256).
 *
 * @param ucV Byte de entrada
 * @return Byte resultante
 */
static uint8_t Mul03(uint8_t ucV)
{
    return (uint8_t)(Mul02(ucV) ^ ucV);
}

/**
 * @brief Executa a etapa MixColumns do AES.
 *
 * @param pucS Ponteiro para estrutura de bytes a ser misturada
 */
static void MixColumns(uxConverter *pucS)
{
    uint8_t ucT0 = Mul02(pucS->ui8_0) ^ Mul03(pucS->ui8_1) ^ (pucS->ui8_2) ^ (pucS->ui8_3);
    uint8_t ucT1 = (pucS->ui8_0) ^ Mul02(pucS->ui8_1) ^ Mul03(pucS->ui8_2) ^ (pucS->ui8_3);
    uint8_t ucT2 = (pucS->ui8_0) ^ (pucS->ui8_1) ^ Mul02(pucS->ui8_2) ^ Mul03(pucS->ui8_3);
    uint8_t ucT3 = Mul03(pucS->ui8_0) ^ (pucS->ui8_1) ^ (pucS->ui8_2) ^ Mul02(pucS->ui8_3);
    pucS->ui8_0 = ENDIAN ? ucT3 : ucT0;
    pucS->ui8_1 = ENDIAN ? ucT2 : ucT1;
    pucS->ui8_2 = ENDIAN ? ucT1 : ucT2;
    pucS->ui8_3 = ENDIAN ? ucT0 : ucT3;
}

/**
 * @brief Etapa Q da cifra, aplica S-Box e MixColumns.
 *
 * @param pui32Buf Buffer de 32 bits a ser transformado
 */
static void FunctionQ(uxConverter *pui32Buf)
{
	if(ENDIAN)
		pui32Buf->ui32 = __builtin_bswap32(pui32Buf->ui32);

	pui32Buf->ui8_0 = g_AesSBox[pui32Buf->ui8_0];
	pui32Buf->ui8_1 = g_AesSBox[pui32Buf->ui8_1];
	pui32Buf->ui8_2 = g_AesSBox[pui32Buf->ui8_2];
	pui32Buf->ui8_3 = g_AesSBox[pui32Buf->ui8_3];
	MixColumns(pui32Buf);
}

/**
 * @brief Realiza a rotação utilizada na etapa R da cifra.
 *
 * @param pui32Buf Buffer de 64 bits para rotação
 */
static void FunctionR(uxConverter *pui32Buf)
{
	uint16_t aucS = pui32Buf[0].ui16_1;
	pui32Buf[0].ui16_1 = pui32Buf[1].ui16_1;
	pui32Buf[1].ui16_1 = aucS;
}

/**
 * @brief Função G da cifra.
 *
 * Aplica as etapas Q e R combinadas com a chave da rodada.
 *
 * @param pui32Output Vetor de saída de 64 bits
 * @param ui32Key     Chave da rodada
 * @param pui32Input  Vetor de entrada de 64 bits
 */
static void FunctionG(uint32_t *pui32Output, uint32_t ui32Key, const uint32_t *pui32Input)
{
    uxConverter ui32Buf[2] = {0};
    ui32Buf[!ENDIAN].ui32 = 0;
    ui32Buf[ENDIAN].ui32 = 0;
    memcpy(ui32Buf, pui32Input, sizeof(ui32Buf));
    ui32Buf[ENDIAN].ui32 ^= ui32Key;
    FunctionQ(&ui32Buf[!ENDIAN]);
    FunctionQ(&ui32Buf[ENDIAN]);
    FunctionR(ui32Buf); // erro antes daqui
    memcpy(pui32Output, ui32Buf, sizeof(ui32Buf));
}

/**
 * @brief Geração das chaves de rodada.
 *
 * @param pui32RoundKey Vetor de saída com as chaves
 * @param pui32Key      Chave mestra de 128 bits
 */
static void KeySchedule(uint32_t *pui32RoundKey, const uint32_t *pui32Key)
{
    uint32_t ui32K[KeyLengthInWord] = {0};
    memcpy(ui32K, pui32Key, sizeof(ui32K));
    uxConverter ui32Buf = {0};

    for (uint32_t uRound = 0; uRound < NumberOfRounds; uRound++) {
        pui32RoundKey[uRound] = ui32K[0];
        ui32Buf.ui32 = C[uRound] ^ ui32K[2];
        FunctionQ(&ui32Buf);
        ui32Buf.ui32 ^= ui32K[3];

        ui32K[3] = ui32K[2];
        ui32K[2] = ui32K[1];
        ui32K[1] = ui32K[0];
        ui32K[0] = ui32Buf.ui32;
    }
}

/**
 * @brief Mistura de mensagem do cifrador.
 *
 * Aplica a função G e permuta os registros do bloco.
 *
 * @param pui32Block    Bloco de dados
 * @param pui32RoundKey Chaves de rodada
 */
static void MessageMixing(uint32_t *pui32Block, const uint32_t *pui32RoundKey)
{
	uint32_t ui32Buf[2] = {0};

    for (uint32_t uRound = 0; uRound < NumberOfRounds; uRound++) {
    	FunctionG(ui32Buf, pui32RoundKey[uRound], pui32Block + 4);
        ui32Buf[!ENDIAN] ^= pui32Block[6];
        ui32Buf[ENDIAN] ^= pui32Block[7];

        pui32Block[7] = pui32Block[5];
        pui32Block[6] = pui32Block[4];
        pui32Block[5] = pui32Block[3];
        pui32Block[4] = pui32Block[2];
        pui32Block[3] = pui32Block[1];
        pui32Block[2] = pui32Block[0];
        pui32Block[1] = ui32Buf[ENDIAN];
        pui32Block[0] = ui32Buf[!ENDIAN];
    }
}

/**
 * @brief Cifra um bloco utilizando as chaves geradas.
 *
 * @param pui32Ciphertext Vetor de saída cifrado
 * @param pui32Key        Chave mestra
 * @param pui32Plaintext  Vetor de entrada claro
 */
static void BlockCipher(uint32_t *pui32Ciphertext, const uint32_t *pui32Key, const uint32_t *pui32Plaintext)
{
    uint32_t ui32RoundKey[NumberOfRounds] = {0};
    KeySchedule(ui32RoundKey, pui32Key);
    uint32_t ui32Block[BlockLengthInWord] = {0};
    memcpy(ui32Block, pui32Plaintext, sizeof(ui32Block));
    MessageMixing(ui32Block, ui32RoundKey);
    memcpy(pui32Ciphertext, ui32Block, sizeof(ui32Block));
}

/*============================*/
/* API do Hash Lesamnta-LW    */
/*============================*/

/**
 * @brief Estado interno do hash
 * 
 */
typedef struct {
    int iHashBitLen;
    uint32_t ui32MessageLength[2];
    uint32_t ui32RemainingLength;
    uint32_t ui32Message[MessageBlockLengthInWord];
    uint32_t ui32Hash[HashLengthInWord];
} hashState;

/**
 * @brief Inicializa a estrutura de estado do hash.
 *
 * @param pState Estrutura de estado
 * @return Código de erro
 */
static HashReturn LesamntaLW_Init(hashState *pState)
{
    pState->iHashBitLen = LESAMNTALW_HASH_BITLENGTH;
    pState->ui32MessageLength[0] = 0;
    pState->ui32MessageLength[1] = 0;
    pState->ui32RemainingLength = 0;
    memset(pState->ui32Message, 0, MessageBlockLengthInByte);
    memcpy(pState->ui32Hash, ui32InitialValue, HashLengthInByte);

    return SUCCESS_;
}

/**
 * @brief Converte dados de entrada em vetor de palavras.
 *
 * @param pui32Message Vetor de saída em palavras
 * @param pcData       Dados de entrada em bytes
 */
static void SetMessage(uint32_t *pui32Message, const BitSequence *pcData)
{
    memset(pui32Message, 0, MessageBlockLengthInByte);
    for (int i = 0; i < MessageBlockLengthInByte; i++) {
        pui32Message[i / 4] |= ((uint32_t)pcData[i]) << (24 - 8 * (i % 4));
    }
}

/**
 * @brief Preenche bloco parcial da mensagem.
 *
 * @param pui32Message        Vetor de saída
 * @param ui32RemainingLength Tamanho restante em bits
 * @param pcData              Dados de entrada
 */
static void SetRemainingMessage(uint32_t *pui32Message, uint32_t ui32RemainingLength, const BitSequence *pcData)
{
    memset(pui32Message, 0, MessageBlockLengthInByte);
    int iLast = ui32RemainingLength / 8 + ((ui32RemainingLength % 8 == 0) ? -1 : 0);
    for (int i = 0; i <= iLast; i++) {
        pui32Message[i / 4] |= ((uint32_t)pcData[i]) << (24 - 8 * (i % 4));
    }
}

/**
 * @brief Função de compressão do Lesamnta-LW.
 *
 * @param pui32Hash    Vetor do hash em palavras
 * @param pui32Message Bloco de mensagem
 */
static void CompressionFunction(uint32_t *pui32Hash, const uint32_t *pui32Message)
{
    uint32_t ui32Key[KeyLengthInWord] = {0};
    uint32_t ui32Plaintext[BlockLengthInWord] = {0};
    memcpy(ui32Key, pui32Hash, sizeof(ui32Key));
    memcpy(ui32Plaintext, pui32Message, sizeof(ui32Plaintext) / 2);
    memcpy(ui32Plaintext + 4, pui32Hash + 4, sizeof(ui32Plaintext) / 2);
    uint32_t ui32Ciphertext[BlockLengthInWord] = {0};
    BlockCipher(ui32Ciphertext, ui32Key, ui32Plaintext);
    memcpy(pui32Hash, ui32Ciphertext, sizeof(ui32Ciphertext));
}

/**
 * @brief Processa dados de entrada em blocos.
 *
 * @param pState        Estado interno
 * @param pcData        Dados de entrada
 * @param dlDataBitLen  Tamanho em bits
 * @return Código de erro
 */
static HashReturn LesamntaLW_Update(hashState *pState, const BitSequence *pcData, DataLength dlDataBitLen)
{
    pState->ui32MessageLength[0] = (uint32_t)(dlDataBitLen >> 32);
    pState->ui32MessageLength[1] = (uint32_t)dlDataBitLen;

    while (dlDataBitLen >= MessageBlockLengthInBit) {
    	SetMessage(pState->ui32Message, pcData);
    	CompressionFunction(pState->ui32Hash, pState->ui32Message);
        pcData += MessageBlockLengthInByte;
        dlDataBitLen -= MessageBlockLengthInBit;
    }

    pState->ui32RemainingLength = dlDataBitLen;
    memset(pState->ui32Message, 0, MessageBlockLengthInByte);
    if (pState->ui32RemainingLength != 0)
    	SetRemainingMessage(pState->ui32Message, pState->ui32RemainingLength, pcData);

    return SUCCESS_;
}

/**
 * @brief Aplica o padding final na mensagem.
 *
 * @param pui32Message        Vetor de mensagem
 * @param ui32RemainingLength Comprimento restante em bits
 */
static void PaddingMessage(uint32_t *pui32Message, uint32_t ui32RemainingLength)
{
    int iLast = ui32RemainingLength / 32;
    pui32Message[iLast] |= 0x00000001U << (31 - (ui32RemainingLength % 32));
}

/**
 * @brief Converte vetor de palavras de hash para sequência de bytes.
 *
 * @param pcHashVal Vetor de saída em bytes
 * @param pui32Hash Vetor de hash em palavras
 */
static void ToBitSequence256(BitSequence *pcHashVal, const uint32_t *pui32Hash)
{
    for (int i = 0; i < HashLengthInByte; i += 4) {
        pcHashVal[i+0] = (BitSequence)(pui32Hash[i/4] >> 24);
        pcHashVal[i+1] = (BitSequence)(pui32Hash[i/4] >> 16);
        pcHashVal[i+2] = (BitSequence)(pui32Hash[i/4] >> 8);
        pcHashVal[i+3] = (BitSequence)(pui32Hash[i/4]);
    }
}

/**
 * @brief Finaliza o cálculo do hash.
 *
 * @param pState    Estado interno
 * @param pcHashVal Buffer de saída do hash
 * @return Código de erro
 */
static HashReturn LesamntaLW_Final(hashState *pState, BitSequence *pcHashVal)
{
    if (pState->ui32RemainingLength == 0)
        pState->ui32Message[0] = 0x80000000U;
    else {
    	PaddingMessage(pState->ui32Message, pState->ui32RemainingLength);
        CompressionFunction(pState->ui32Hash, pState->ui32Message);
        pState->ui32Message[0] = 0x00000000U;
    }
    pState->ui32Message[1] = 0x00000000U;
    pState->ui32Message[2] = pState->ui32MessageLength[0];
    pState->ui32Message[3] = pState->ui32MessageLength[1];

    CompressionFunction(pState->ui32Hash, pState->ui32Message);
    pState->ui32RemainingLength = 0;
    memset(pState->ui32Message, 0, sizeof(pState->ui32Message));

    ToBitSequence256(pcHashVal, pState->ui32Hash);

    return SUCCESS_;
}

/**
 * @brief Função de alto nível para cálculo do hash Lesamnta-LW.
 *
 * @param pcData       Dados de entrada
 * @param dlDataBitLen Tamanho em bits
 * @param pcHashVal    Buffer para o hash de saída
 * @return Código de erro
 */
HashReturn LesamntaLW_Hash(const BitSequence *pcData, DataLength dlDataBitLen, BitSequence *pcHashVal)
{
	hashState xState;
	HashReturn eRet = LesamntaLW_Init(&xState);
    if (eRet != SUCCESS_)
        return eRet;
    eRet = LesamntaLW_Update(&xState, pcData, dlDataBitLen);
    if (eRet != SUCCESS_)
        return eRet;
    eRet = LesamntaLW_Final(&xState, pcHashVal);
    if (eRet != SUCCESS_)
        return eRet;

    return SUCCESS_;
}
