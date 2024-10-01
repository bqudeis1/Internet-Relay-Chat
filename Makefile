CC = g++
CFLAGS = -pthread
CLIENT_SRC = client.cpp
SERVER_SRC = server.cpp

all: client server

client: $(CLIENT_SRC)
	$(CC) $(CFLAGS) $(CLIENT_SRC) -o client

server: $(SERVER_SRC)
	$(CC) $(CFLAGS) $(SERVER_SRC) -o server

clean:
	rm -f client server