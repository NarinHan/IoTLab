#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
	 
int main(int argc, char *argv[])
{
    struct ifreq *ifr;
    struct sockaddr_in *sin;
    struct sockaddr *sa;
    struct ifconf ifcfg;

    int fd;
    int n;
    int numreqs = 30;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
 
    memset(&ifcfg, 0, sizeof(ifcfg));
    ifcfg.ifc_buf = NULL;
    ifcfg.ifc_len = sizeof(struct ifreq) * numreqs;
    ifcfg.ifc_buf = malloc(ifcfg.ifc_len);
 
    ifcfg.ifc_len = sizeof(struct ifreq) * numreqs;
    ifcfg.ifc_buf = realloc(ifcfg.ifc_buf, ifcfg.ifc_len);
    if (ioctl(fd, SIOCGIFCONF, (char *)&ifcfg) < 0) {
        perror("SIOCGIFCONF ");
        exit(1);
    }

    ifr = ifcfg.ifc_req;
    for (n = 0; n < ifcfg.ifc_len; n += sizeof(struct ifreq)) {
        printf("[%s]\n", ifr->ifr_name);
        sin = (struct sockaddr_in *)&ifr->ifr_addr;
        printf("IP    %s \n", inet_ntoa(sin->sin_addr));
        if (ntohl(sin->sin_addr.s_addr) == INADDR_LOOPBACK) {
            printf("Loop Back\n");
        } else {
            ioctl(fd, SIOCGIFHWADDR, (char *)ifr);
            sa = &ifr->ifr_hwaddr;
            printf("MAC   %s\n", ether_ntoa((struct ether_addr *)sa->sa_data));
        }
        
        ioctl(fd, SIOCGIFBRDADDR, (char *)ifr);
        sin = (struct sockaddr_in *)&ifr->ifr_broadaddr;
        printf("BROD  %s\n", inet_ntoa(sin->sin_addr));
        
        ioctl(fd, SIOCGIFNETMASK, (char *)ifr);
        sin = (struct sockaddr_in *)&ifr->ifr_addr;
        printf("MASK  %s\n", inet_ntoa(sin->sin_addr));
        
        ioctl(fd, SIOCGIFMTU, (char *)ifr);
        printf("MTU   %d\n", ifr->ifr_mtu);
        printf("\n");
        
        ifr++;
    }

    return 0;
}

