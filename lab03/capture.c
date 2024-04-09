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
// void print_ip_header(char* buffer);
// void print_tcp_packet(char* buffer);

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
    printf("   |-Protocol                : %u \n", (unsigned short)eth->h_proto);

    // Check if the next layer is an IP packet based on the EtherType
    // TODO
}


/* Please uncomment below lines for lab 

void print_ip_header(char* buffer) {
    // TODO 
    // Hint: struct iphdr 

}


void print_tcp_packet(char* buffer) {
    // TODO 
    // Hint: struct tcphdr 

}
*/