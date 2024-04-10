#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define BUF_SIZE 1024

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
unsigned short checksum(const char *data, size_t len)
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

void create_IP_header(struct iphdr *iph, int pkt_type, struct sockaddr_in *src, struct sockaddr_in *dst) 
{
	iph->version = 4 ;
	iph->ihl = 5 ;
	iph->tos = 0 ;
	iph->tot_len = sizeof(struct iphdr) ;
	if (pkt_type == SYN) {
		iph->id = htonl(rand() % 65535) ; 
	} else {
		iph->id += 1 ;
	}
	iph->frag_off = 1 << 14 ; // Don't Fragment mode = Bit1 ON
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
		tcph->seq = htonl(*seqnum) ;
		tcph->ack_seq = htonl(0) ;
		tcph->ack = 0 ;
		tcph->psh = 0 ;
		tcph->syn = 1 ;
	} else if (pkt_type == ACK) {
		tcph->seq = htonl(*seqnum + 1) ;
		tcph->ack_seq = htonl(*acknum + 1) ;
		tcph->ack = 1 ;
		tcph->psh = 0 ;
		tcph->syn = 0 ;     
	} else if (pkt_type == DATA) {
		tcph->seq = htonl(*seqnum + 1) ;
		tcph->ack_seq = htonl(*acknum + 1) ;
		tcph->ack = 1 ;
		tcph->psh = 1 ;
		tcph->syn = 0 ;
	}
	tcph->doff = 5 ;
	tcph->urg = 0 ;
	tcph->rst = 0 ;
	tcph->fin = 0 ;
	tcph->window = htons(16384) ;
	tcph->check = 0 ;
	tcph->urg_ptr = 0 ;	
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
	pseudo_header_t phdr ;
	phdr.src_addr = saddr.sin_addr.s_addr ;
	phdr.dest_addr = daddr.sin_addr.s_addr ;
	phdr.reserved = 0 ;
	phdr.proto = IPPROTO_TCP ;

	// IP header, TCP header, sequence number, ack number
	struct iphdr iph ;
	struct tcphdr tcph ;
	uint32_t seqn = 0 ; 
	uint32_t ackn = 0 ;

	// TCP Three-way Handshaking 
	// Step 1. Send SYN (no need to use TCP options)
	create_IP_header(&iph, SYN, &saddr, &daddr) ;
	create_TCP_header(&tcph, SYN, &saddr, &daddr, &seqn, &ackn) ;
	printf("seqn : %d     ackn : %d\n", ntohl(seqn), ntohl(ackn)) ;

	// Create and fill tcp pseudo segment
	char *pseudo_seg = malloc(sizeof(pseudo_header_t) + sizeof(struct tcphdr)) ; // treat contents of TCP segment including pseudo header as sequence of 16-bit integers
	if (pseudo_seg == NULL) {
		perror("memory allocation error ") ;
		exit(EXIT_FAILURE) ;
	}
	phdr.length = htons(sizeof(struct tcphdr)) ;
	memcpy(pseudo_seg, &phdr, sizeof(pseudo_header_t)) ;
	memcpy(pseudo_seg + sizeof(pseudo_header_t), &tcph, sizeof(struct tcphdr)) ;

	// Calculate checksum for tcp and ip
	tcph.check = htons(checksum(pseudo_seg, sizeof(pseudo_seg))) ;
	iph.check = htons(checksum(&iph, sizeof(struct iphdr))) ;
	printf("tcp checksum : 0x%04X\n", ntohs(tcph.check)) ;
	printf("ip checksum : 0x%04X\n", ntohs(iph.check)) ;
	
	// Create and fill syn packet
	size_t packet_len = sizeof(struct iphdr) + sizeof(struct tcphdr) ;
	char *syn_packet = malloc(packet_len) ;
	if (syn_packet == NULL) {
		perror("memory allocation error ") ;
		exit(EXIT_FAILURE) ;
	}
	memcpy(syn_packet, &iph, sizeof(struct iphdr)) ;
	memcpy(syn_packet + sizeof(struct iphdr), &tcph, sizeof(struct tcphdr)) ;

	// Send the syn packet
	int sent = 0 ;
	if (sent = sendto(sock, syn_packet, packet_len, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr)) == -1) {
		perror("SYN sendto failed ") ;
		exit(EXIT_FAILURE) ;
	} 
	printf("SYN packet sent...\n") ;
	
	free (pseudo_seg) ;
	free (syn_packet) ;
	

	// Step 2. Receive SYN-ACK
	// Step 3. Send ACK 

	// Data transfer 
	char message[BUF_SIZE];
	while (1) 
	{
		fputs("Input message(Q to quit): ", stdout);
		fgets(message, BUF_SIZE, stdin);
		
		if (!strcmp(message,"q\n") || !strcmp(message,"Q\n"))
			break;

		// Step 4. Send an application message (with PSH and ACK flag)! 
		
		// Step 5. Receive ACK 
	}

	close(sock);
	return 0;
}