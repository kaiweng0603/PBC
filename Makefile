
CC=gcc

TARGET=BLS

LIBS=-lpbc -lgmp

all:
	$(CC) BLS.c -o $(TARGET) $(LIBS)

run:
	./$(TARGET)

clean:
	rm -f $(TARGET)

