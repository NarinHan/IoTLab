#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define BUF_SIZE 4096

// Before run this code, execute the command below 
// This is to install firewall so that OS does not take the packet
// $ sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

typedef enum {
	SYN,
	SYNACK,
	ACK,
	DATA
} Pkt_type ;

// TODO: pseudo header needed for tcp header checksum calculation
typedef struct pseudo_header {
	uint32_t src_addr ; // unsigned int
	uint32_t dest_addr ;
	uint8_t reserved ; // unsigned char
	uint8_t proto ;
	uint16_t length ; // tcp header length + data length in octets
} pseudo_header_t ;

// Checksum needs to be accurately calculated, otherwise server may drop the packet
// TODO: Define checksum function which returns unsigned short value 
unsigned short checksum(const void *data, size_t len)
{
	unsigned long sum = 0 ;
	unsigned short *buf = data ;

	// Sum all the 16-bit words
	while (len > 1) {
		sum += *buf++ ;
		len -= 2 ;
	}

	// Add the last byte, if present
	if (len == 1) {
		sum += *((unsigned char *)buf) ;
	}

	// Fold 32-bit sum to 16 bits : for carry wrap around
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16) ;
	}
	
	return (unsigned short)~sum ;	
}

void create_IP_header(struct iphdr *iph, int pkt_type, size_t data_len, struct sockaddr_in *src, struct sockaddr_in *dst) 
{
	iph->version = 4 ;
	iph->ihl = 5 ;
	iph->tos = 0 ;
	iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len) ;
	if (pkt_type == SYN) {
		iph->id = htons(rand() % 65535) ; 
	} else {
		iph->id = htons(iph->id + 1) ;
	}
	iph->frag_off = htons(1 << 14) ; // Don't Fragment mode = Bit1 ON
	iph->ttl = 128 ; // any good number [64, 128]
	iph->protocol = IPPROTO_TCP ;
	iph->saddr = src->sin_addr.s_addr ;
	iph->daddr = dst->sin_addr.s_addr ;
}

void create_TCP_header(struct tcphdr *tcph, int pkt_type, struct sockaddr_in *src, struct sockaddr_in *dst, uint32_t *seqnum, uint32_t *acknum)
{
	tcph->source = src->sin_port ;
	tcph->dest = dst->sin_port ;
	if (pkt_type == SYN) {
		*seqnum = rand() % 16777215 ;
		tcph->ack_seq = htonl(*acknum) ;
		tcph->ack = 0 ;
		tcph->psh = 0 ;
		tcph->syn = 1 ;
	} else if (pkt_type == ACK) {
		tcph->ack_seq = htonl(*acknum + 1) ;
		tcph->ack = 1 ;
		tcph->psh = 0 ;
		tcph->syn = 0 ;     
	} else if (pkt_type == DATA) {
		tcph->ack_seq = htonl(*acknum) ;
		tcph->ack = 1 ;
		tcph->psh = 1 ;
		tcph->syn = 0 ;
	}
	tcph->seq = htonl(*seqnum) ;
	tcph->doff = 5 ;
	tcph->urg = 0 ;
	tcph->rst = 0 ;
	tcph->fin = 0 ;
	tcph->window = htons(16384) ;
	tcph->check = 0 ; // for now, it will be calculated later
	tcph->urg_ptr = 0 ;	
}

// This function will create pseudo segment, calculate checksum of tcp/ip, and create packets
void create_packet(char *pseudo_seg, char *packet, struct iphdr *iph, struct tcphdr *tcph, pseudo_header_t *ph, char *data, size_t data_len) 
{
	// Fill tcp pseudo segment
	ph->length = htons(sizeof(struct tcphdr) + data_len) ;
	memcpy(pseudo_seg, ph, sizeof(pseudo_header_t)) ;
	memcpy(pseudo_seg + sizeof(pseudo_header_t), tcph, sizeof(struct tcphdr)) ;
	memcpy(pseudo_seg + sizeof(pseudo_header_t) + sizeof(struct tcphdr), data, data_len) ;
	
	// Calculate checksum for tcp and ip
	tcph->check = checksum(pseudo_seg, sizeof(pseudo_header_t) + sizeof(struct tcphdr) + data_len) ;
	iph->check = checksum(iph, sizeof(struct iphdr)) ;
	printf("tcp checksum : 0x%04X\n", ntohs(tcph->check)) ;
	printf("ip checksum : 0x%04X\n", ntohs(iph->check)) ;
	
	// Fill packet
	memcpy(packet, iph, sizeof(struct iphdr)) ;
	memcpy(packet + sizeof(struct iphdr), tcph, sizeof(struct tcphdr)) ;
	memcpy(packet + sizeof(struct iphdr) + sizeof(struct tcphdr), data, data_len) ;
}

int read_synack(const char * buffer, uint32_t *seqnum, uint32_t *acknum)
{
	// ACKnum(received) == Seq(sent) + 1
	// Seq(received) + 1 == ACKnum(will send)
	
	// if (recv_bytes = recvfrom(sock, buffer, BUF_SIZE, 0, (struct sockaddr *)&daddr, &addr_len) == -1) {
	// 	perror("SYNACK recvfrom failed ") ;
	// 	exit(EXIT_FAILURE) ;
	// }

	struct iphdr iph ;
	struct tcphdr tcph ;

	memcpy(&iph, buffer, sizeof(struct iphdr)) ;
	memcpy(&tcph, buffer + (iph.ihl * 4), sizeof(struct tcphdr)) ;

	// Q. Do I have to check the protocol or the SYN/ACK bit on?

	*seqnum = ntohl(tcph.ack_seq) ; // ACKnum(received) == Seq(sent) + 1
	*acknum = ntohl(tcph.seq) ;	

	printf("seqnum received: %u\n", ntohl(tcph.seq)) ;
	printf("acknum received: %u\n", ntohl(tcph.ack_seq)) ;

	return 0 ;
}

int main(int argc, char *argv[])
{
	if (argc != 4)
	{
		printf("Usage: %s <Source IP> <Destination IP> <Destination Port>\n", argv[0]);
		return 1;
	}

	srand(time(NULL));

	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock == -1)
	{
		perror("socket");
        exit(EXIT_FAILURE);
	}

	// Source IP
	struct sockaddr_in saddr;
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(rand() % 65535); // random client port
	if (inet_pton(AF_INET, argv[1], &saddr.sin_addr) != 1)
	{
		perror("Source IP configuration failed\n");
		exit(EXIT_FAILURE);
	}

	// Destination IP and Port 
	struct sockaddr_in daddr;
	daddr.sin_family = AF_INET;
	daddr.sin_port = htons(atoi(argv[3]));
	if (inet_pton(AF_INET, argv[2], &daddr.sin_addr) != 1)
	{
		perror("Destination IP and Port configuration failed");
		exit(EXIT_FAILURE);
	}

	// Tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1) // implement the IP layer
	{
		perror("setsockopt(IP_HDRINCL, 1)");
		exit(EXIT_FAILURE);
	}

	// Set pseudo header
	pseudo_header_t ph ;
	ph.src_addr = saddr.sin_addr.s_addr ;
	ph.dest_addr = daddr.sin_addr.s_addr ;
	ph.reserved = 0 ;
	ph.proto = IPPROTO_TCP ;

	// IP header, TCP header, sequence number, ack number
	struct iphdr iph ;
	struct tcphdr tcph ;
	uint32_t seqn = 0 ; 
	uint32_t ackn = 0 ;

	// Pseudo segment, packet
	char *pseudo_seg ;
	char *packet ;

	// TCP Three-way Handshaking 
	// Step 1. Send SYN (no need to use TCP options)
	create_IP_header(&iph, SYN, 0, &saddr, &daddr) ;
	create_TCP_header(&tcph, SYN, &saddr, &daddr, &seqn, &ackn) ;
	printf("seqn : %u     ackn : %u\n", seqn, ackn) ;

	pseudo_seg = malloc(sizeof(pseudo_header_t) + sizeof(struct tcphdr)) ; // treat contents of TCP segment including pseudo header as sequence of 16-bit integers
	if (pseudo_seg == NULL) {
		perror("memory allocation error ") ;
		exit(EXIT_FAILURE) ;
	}

	packet = malloc(sizeof(struct iphdr) + sizeof(struct tcphdr)) ;
	if (packet == NULL) {
		perror("memory allocation error ") ;
		exit(EXIT_FAILURE) ;
	}

	create_packet(pseudo_seg, packet, &iph, &tcph, &ph, NULL, 0) ; // SYN packet

	// Send SYN packet
	int sent_bytes = 0 ;
	if (sent_bytes = sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr)) == -1) {
		perror("SYN sendto failed ") ;
		exit(EXIT_FAILURE) ;
	} 
	printf("...SYN packet succesfully sent...\n") ;
	 
	// Step 2. Receive SYN-ACK
	char buffer[BUF_SIZE] ;
	int recv_bytes = 0 ;
	while (1) {
		if ((recv_bytes = recv(sock, buffer, BUF_SIZE, 0)) == -1) {
			perror("SYN-ACK receving error ") ;
			exit(EXIT_FAILURE) ;
		}
		uint16_t temp ; 
		memcpy(&temp, buffer + 22, sizeof(uint16_t)) ;
		if (saddr.sin_port == temp) { // raw socket receives literally every packet
			break ;
		} 
	}
	
	if (read_synack(buffer, &seqn, &ackn) == -1) {
		perror("SYNACK received is not correct ") ;
		exit(EXIT_FAILURE) ;
	}

	// Step 3. Send ACK 
	create_IP_header(&iph, ACK, 0, &saddr, &daddr) ;
	create_TCP_header(&tcph, ACK, &saddr, &daddr, &seqn, &ackn) ;
	
	memset(pseudo_seg, 0, sizeof(pseudo_header_t) + sizeof(struct tcphdr)) ;
	memset(packet, 0, sizeof(struct iphdr) + sizeof(struct tcphdr)) ;

	create_packet(pseudo_seg, packet, &iph, &tcph, &ph, NULL, 0) ; // ACK packet

	// Send ACK packet
	if (sent_bytes = sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr)) == -1) {
		perror("ACK sendto failed ") ;
		exit(EXIT_FAILURE) ;
	}
	printf("...ACK packet succesfully sent...\n") ;

	free (pseudo_seg) ;
	free (packet) ;

	// Data transfer 
	char message[BUF_SIZE];
	while (1) 
	{
		fputs("Input message(Q to quit): ", stdout);
		fgets(message, BUF_SIZE, stdin);
		
		if (!strcmp(message,"q\n") || !strcmp(message,"Q\n"))
			break;

		// Step 4. Send an application message (with PSH and ACK flag)! 
		size_t msg_len = strlen(message) ;
		create_IP_header(&iph, DATA, msg_len, &saddr, &daddr) ;
		create_TCP_header(&tcph, DATA, &saddr, &daddr, &seqn, &ackn) ;

		pseudo_seg = malloc(sizeof(pseudo_header_t) + sizeof(struct tcphdr) + msg_len) ;
		if (pseudo_seg == NULL) {
			perror("memory allocation error ") ;
			exit(EXIT_FAILURE) ;
		}

		packet = malloc(sizeof(struct iphdr) + sizeof(struct tcphdr) + msg_len) ;
		if (packet == NULL) {
			perror("memory allocation error ") ;
			exit(EXIT_FAILURE) ;
		}

		create_packet(pseudo_seg, packet, &iph, &tcph, &ph, message, msg_len) ;

		// Send DATA packet
		if (sent_bytes = sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + msg_len, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr)) == -1) {
			perror("DATA sendto failed ") ;
			exit(EXIT_FAILURE) ;
		}
		printf("...DATA packet succesfully sent...\n") ;

		free (pseudo_seg) ;
		free (packet) ;

		// Step 5. Receive ACK
		memset(buffer, 0, BUF_SIZE) ;
		while (1) {
			if ((recv_bytes = recv(sock, buffer, BUF_SIZE, 0)) == -1) {
				perror("ACK receving error ") ;
				exit(EXIT_FAILURE) ;
			}
			uint16_t temp ;
			memcpy(&temp, buffer + 22, sizeof(uint16_t)) ;
			if (saddr.sin_port == temp) {
				break ;
			} 
		}
		
		printf("Received ACK buffer:\n");
		for (size_t i = 0; i < sizeof(struct iphdr) + sizeof(struct tcphdr); i++) {
			printf("%02X ", (unsigned char)buffer[i]);
			if ((i + 1) % 16 == 0) {
				printf("\n");
			}
		}
		printf("\n");
			
		if (read_synack(buffer, &seqn, &ackn) == -1) {
			perror("SYNACK received is not correct ") ;
			exit(EXIT_FAILURE) ;
		} 
	}

	close(sock);
	return 0;
}
