# Nom de l'exécutable final
TARGET = program

# Compilateur et options de compilation
CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lssl -lcrypto

# Fichiers sources et fichiers objets
SRCS = main.c functions.c
OBJS = $(SRCS:.c=.o)

# Règle principale
all: $(TARGET)

# Compilation de l'exécutable
$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

# Compilation des fichiers objets
%.o: %.c passfun.h
	$(CC) $(CFLAGS) -c $< -o $@

# Nettoyage des fichiers objets et de l'exécutable
clean:
	rm -f $(OBJS) $(TARGET)

# Pour forcer la recompilation
rebuild: clean all
