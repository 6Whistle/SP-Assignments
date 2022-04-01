OBJ = proxy_cache.c
RUN = proxy_cache
CC = gcc
OPT = -o
SHA = -lcrypto

all : $(OBJ)
	$(CC) $(OPT) $(RUN) $^ $(SHA)

clean :
	rm -rf $(RUN)
