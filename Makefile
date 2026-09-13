all:
	$(CC) $(CFLAGS) -o zdecrypt zdecrypt.c -lssl -lcrypto -ljson-c
clean:
	$(RM) -f zdecrypt
