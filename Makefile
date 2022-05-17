OBJ1 = proxy_cache.c
RUN1 = proxy_cache
CC = gcc
OPT = -o
SHA = -lcrypto

all: $(RUN1)

$(RUN1): $(OBJ1)
	$(CC) $(OPT) $@ $^ $(SHA)

clean :
	rm -rf $(RUN1)