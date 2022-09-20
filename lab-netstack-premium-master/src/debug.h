#ifndef MYDEBUG_H
#define MYDEBUG_H


#include <netinet/ether.h>
#include <arpa/inet.h>

const uint32_t sizethhdr = sizeof(struct ethhdr);

typedef int (*frameReceiveCallback)(const void*, const void*, int, int);

#define BYTE_IN_ROW 0x10
#define errhandle(...) {\
    fprintf(stderr,__VA_ARGS__);\
    return -1;\
}

#define printmac(mac_addr); printf(\
    "%02x:%02x:%02x:%02x:%02x:%02x",\
    (unsigned char)mac_addr[0],(unsigned char)mac_addr[1],(unsigned char)mac_addr[2],\
    (unsigned char)mac_addr[3],(unsigned char)mac_addr[4],(unsigned char)mac_addr[5]);

#endif