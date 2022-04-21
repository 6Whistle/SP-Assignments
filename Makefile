OBJ1 = server.c
OBJ2 = client.c
RUN1 = server
RUN2 = client
CC = gcc
OPT = -o
SHA = -lcrypto

all: $(RUN1) $(RUN2)

$(RUN1): $(OBJ1)
	$(CC) $(OPT) $@ $^ $(SHA)

$(RUN2): $(OBJ2)
	$(CC) $(OPT) $@ $^
	
clean :
	rm -rf $(RUN1) $(RUN2)
