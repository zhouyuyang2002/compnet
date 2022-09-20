#ifndef NAME2MAC_H
#define NAME2MAC_H

#include "debug.h"
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>


int findMac(const char* device, uint8_t* mac_addr){
    struct ifreq ifr;
    int sockfid;

    sockfid = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name) - 1);
    if (ioctl(sockfid, SIOCGIFHWADDR, &ifr) == -1){
        perror("iotcl error ");
        return -1;
    }
    memcpy(mac_addr, ifr.ifr_addr.sa_data, sizeof(unsigned char) * 6);
    return 0;
}
#endif