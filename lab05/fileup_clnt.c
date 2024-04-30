#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BUF_SIZE 512
void error_handling(char *message);

int main(int argc, char *argv[])
{
	int sd;
	FILE *fp;
	
	char file_name[BUF_SIZE];
	char buf[BUF_SIZE];
	int read_cnt;
	struct sockaddr_in serv_adr;
	if (argc != 4) {
		printf("Usage: %s <Server IP> <Server Port> <File Name> \n", argv[0]);
		exit(1);
	}

	strcpy(file_name, argv[3]);
	fp = fopen(argv[3], "rb");
	sd = socket(PF_INET, SOCK_STREAM, 0);   

	memset(&serv_adr, 0, sizeof(serv_adr));
	serv_adr.sin_family = AF_INET;
	serv_adr.sin_addr.s_addr = inet_addr(argv[1]);
	serv_adr.sin_port = htons(atoi(argv[2]));

	connect(sd, (struct sockaddr*)&serv_adr, sizeof(serv_adr));
	
	// send file name length to server 
    int filename_len = strlen(file_name) ;
    write(sd, &filename_len, sizeof(int)) ;
	
	// send file name to server
	write(sd, file_name, filename_len);

	int sent = 0 ;
	// send file data 
	while (1) { 
		read_cnt = fread((void *)buf, 1, BUF_SIZE, fp);
		sent += read_cnt ;
		if (read_cnt < BUF_SIZE) {
			write(sd, buf, read_cnt);
			break;
		}
		write(sd, buf, BUF_SIZE);
	}

	printf("Send total %d bytes \n", sent);

	shutdown(sd, SHUT_WR);

	// read complete message from server 
	read(sd, buf, BUF_SIZE);

	printf("Message from server: %s \n", buf);

	fclose(fp);
	close(sd);
	return 0;
}

void error_handling(char *message)
{
	fputs(message, stderr);
	fputc('\n', stderr);
	exit(1);
}