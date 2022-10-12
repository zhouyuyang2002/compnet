/* *
* @file name2mac.h
* @brief find the Mac & IP Address of specific device
*/

#ifndef NAME2MAC_H
#define NAME2MAC_H

#include "macro.h"
#include <cstring>
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

/* *
* find the Mac Address of specific device
* @param device the name of the device request for Mac address
* @param mac_addr the pointer to the memory used to save the Mac address
* @return 0 on success, 1 on failure.
*/
int findMac(const char* device, uint8_t* mac_addr){
    struct ifreq ifr;
    int sockfid;

    sockfid = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name) - 1);
    if (ioctl(sockfid, SIOCGIFHWADDR, &ifr) == -1) return -1;
    memcpy(mac_addr, ifr.ifr_addr.sa_data, sizeof(unsigned char) * 6);
    return 0;
}


/* *
* find the IP Address of specific device
* @param device the name of the device request for Mac address
* @param ip_addr the pointer to the memory used to save the IP address
* @return 0 on success, -1 on failure.
*/
int findIP(const char* device, struct in_addr &ip_addr){
    struct ifreq ifr;
    int sockfid;

    sockfid = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name) - 1);
    if (ioctl(sockfid, SIOCGIFADDR, &ifr) == -1) return -1;
    struct sockaddr_in sin;
    memcpy(&sin, &ifr.ifr_dstaddr, sizeof(struct sockaddr_in));
    ip_addr.s_addr = ntohl(sin.sin_addr.s_addr);
    return 0;
}
#endif