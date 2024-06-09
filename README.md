Openssl must be installed for development. The download link is given below.
https://slproweb.com/products/Win32OpenSSL.html

Compile options:

gcc -Wall -o client  client.c -L/usr/lib -lssl -lcrypto -lws2_32
gcc -Wall -o server server.c -L/usr/lib -lssl -lcrypto -lws2_32

server.exe should be run first, then client exe should be run.
