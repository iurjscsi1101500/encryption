# Makefile

CC = gcc
CFLAGS = -O3 -std=c23 -Wno-deprecated-declarations
LDFLAGS = -lssl -lcrypto

TARGET = test
SRC = main.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o

