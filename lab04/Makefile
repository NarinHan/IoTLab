all: serv clnt clntraw

serv:
	gcc tcp_server.c -o serv

clnt:
	gcc tcp_client.c -o clnt

clntraw:
	gcc tcp_client_raw.c -o clntraw

clean:
	rm serv clnt clntraw
