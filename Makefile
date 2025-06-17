CC = gcc
CFLAGS = -Wall -Wextra -std=c11

SRC_DIR := algoritmo_chima
SRCS := $(SRC_DIR)/autentication.c \
        $(SRC_DIR)/chima_crypto.c \
        $(SRC_DIR)/chima_genkey.c \
        $(SRC_DIR)/DrvH_PRINT.c \
        $(SRC_DIR)/utils.c \
        $(SRC_DIR)/main_exemplo.c

OBJS := $(SRCS:.c=.o)

TARGET := chima_demo

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -lm -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@


clean:
	$(RM) $(OBJS) $(TARGET)

.PHONY: all clean
