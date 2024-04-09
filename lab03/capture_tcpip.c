#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <arpa/inet.h> 

#define BUFFER_SIZE 65536

void print_ethernet_header(char* buffer);

// Please uncomment below lines for lab 
void print_ip_header(char* buffer);
void print_tcp_packet(char* buffer);

int main(int argc, char *argv[]) {
    int raw_socket;
    int num_packets;
    char buffer[BUFFER_SIZE];
    char *interface_name = NULL; 
    struct ifreq ifr;

    if (argc < 2) {
        printf("Usage: %s <Network Interface> \n", argv[0]);
        return -1;
    }

    interface_name = argv[1]; 

    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_socket < 0) {
        perror("Failed to create raw socket");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_name, sizeof(ifr.ifr_name) - 1);
    if (setsockopt(raw_socket, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
        perror("Failed to bind raw socket to interface");
        close(raw_socket);
        return -1;
    }

    num_packets = 0;
    while (1) {
        ssize_t length = recv(raw_socket, buffer, BUFFER_SIZE, 0);
        if (length < 0) {
            perror("Failed to receive frame");
            break;
        }

        printf("============================================ \n"); 
        printf("Packet No: %d \n", num_packets);  
        print_ethernet_header(buffer);
        printf("============================================ \n\n"); 

        num_packets++;        
    }

    close(raw_socket);

    return 0;
}


void print_ethernet_header(char* buffer) {
    struct ethhdr *eth = (struct ethhdr*)buffer;

    printf("-------------------------------------------- \n");
    printf("Ethernet Header\n");
    printf("   |-Source MAC Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", 
            eth->h_source[0], eth->h_source[1], eth->h_source[2], 
            eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("   |-Destination MAC Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", 
            eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], 
            eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    printf("   |-Protocol                : %u\n", (unsigned short)eth->h_proto);

    // Check if the next layer is an IP packet based on the EtherType
    // TODO
    if (ntohs(eth->h_proto) == ETH_P_IP) {
        print_ip_header(buffer) ;
    }
    
}

void print_ip_header(char* buffer) {
    // TODO 
    // Hint: struct iphdr 
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr)) ; // ethhdr 다음이 iphdr

    printf("-------------------------------------------- \n") ;
    printf("IP Header\n") ;
    printf("   |-Source IP      : %s\n", inet_ntoa(*(struct in_addr *) &ip->saddr)) ;
    printf("   |-Destination IP : %s\n", inet_ntoa(*(struct in_addr *) &ip->daddr)) ;
    printf("   |-Protocol       : %u\n", (unsigned short)ip->protocol) ;

    // Check if the next layer is TCP packet
    if (ip->protocol == IPPROTO_TCP) {
        print_tcp_packet(buffer) ;
    }
}

void print_tcp_packet(char* buffer) {
    // TODO 
    // Hint: struct tcphdr 
    struct tcphdr *tcp = (struct tcphdr *) (buffer + sizeof(struct ethhdr) + sizeof(struct iphdr)) ; // iphdr 다음이 tcphdr

    printf("-------------------------------------------- \n") ;
    printf("TCP Packet\n") ;
    printf("   |-Source Port        : %u\n", ntohs(tcp->source)) ;
    printf("   |-Destination Port   : %u\n", ntohs(tcp->dest)) ;
    printf("   |-Sequence Number    : %u\n", ntohl(tcp->seq)) ; 
    printf("   |-Acknowledge Number : %u\n", ntohl(tcp->ack_seq)) ;
    printf("   |-Flags              : ") ;
    if (tcp->urg) printf("URG ") ; // urgent
    if (tcp->ack) printf("ACK ") ; // acknowledgment
    if (tcp->psh) printf("PSH ") ; // push
    if (tcp->rst) printf("RST ") ; // reset
    if (tcp->syn) printf("SYN ") ; // synchronize
    if (tcp->fin) printf("FIN ") ; // finish
    printf("\n") ;
}