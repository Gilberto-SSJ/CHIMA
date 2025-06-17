# CHIMA

Este repositório contém uma implementação em C de um conjunto de ferramentas criptográficas denominadas **CHIMA**. O projeto inclui geração de chaves pseudoaleatórias, cifragem baseada em Feistel, modos de operação de bloco e função de hash para autenticação.

## Estrutura

Os arquivos do diretório `algoritmo_chima` incluem:

- `chima_genkey.*` – geração de chaves utilizando mapa logístico.
- `chima_crypto.*` – rotinas de cifragem/decifragem e modos de operação.
- `autentication.*` – implementação do hash Lesamnta-LW.
- `utils.*` – funções auxiliares.
- `DrvH_PRINT.*` – driver simples de I/O utilizado nos exemplos.
- `main_exemplo.c` – programa exemplo de uso.

## Compilação

Um *Makefile* está disponível para compilar o exemplo. Basta executar:

```bash
make
```

Será gerado o executável `chima_demo`.

## Execução

```
./chima_demo
```

O programa mostra o processo de geração de chave, cifragem, decifragem e autenticação de diversos valores de ponto flutuante.
