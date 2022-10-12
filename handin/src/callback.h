/* *
* @file callback.h
* @brief Library for callback functions
*/
#ifndef CALLBACK_H
#define CALLBACK_H

#include "arp.h"
#include "ip.h"
#include "device.h"
#include "packetio.h"
#include "name2addr.h"
#include "mytime.h"


/* *
* @brief Example Link Layer Callback function.
* @param __buffer the message from the packet.
* @param __mac_addr the mac address of the source of the packet.
* @param len the length of __buffer
* @param the index of device which receive the packet.
* @return 0 on success, 1 on failure.
*/
int egLinkCallback(const void* __buffer, const void* __mac_addr, int len, int index, uint16_t proto){
    u_char* buffer = (u_char*) __buffer;
    uint8_t* mac_addr = (uint8_t*) __mac_addr;
    printf("Call egLinkCallback()\n");
    printf("proto type: %04x\n", proto);
    printf("receive tic: %lld\n", (long long)gettime());
    printf("Source Mac address:");
    printmac(mac_addr);
    puts("");

    printf("Destination device index: %d\n", index);
    printf("Destination device name: %s\n", d_manager[index]->device_names);
    for (int i = 0; i < len; i++){
        printf("%02x ",(unsigned char)(buffer[i]));
        if ((i + 1) % BYTE_IN_ROW == 0)
            puts("");
    }
    puts("");
    puts("");
    return 0;
}


/* *
* @brief Link Layer Callback function used in 5-layer netstack model
* @param __buffer the message from the packet.
* @param __mac_addr the mac address of the source of the packet.
* @param len the length of __buffer
* @param the index of device which receive the packet.
* @param proto the protocol used in the packet
* @return 0 on success, 1 on failure.
*/
int LinkCallback(const void* __buffer, const void* __mac_addr, int len, int index, uint16_t proto){
    //printf("proto: %04x\n", proto);
    if (proto == ARPPROTOCOL)
        return ARPCallback(__buffer, __mac_addr, len, index);
    if (proto == IPPROTOCOL)
        return IPHandInPacket(__buffer, len);
    return -1;
}

/* *
* @brief Example IP Layer Callback function.
* @param __buffer the message from the packet.
* @param header the header of the IP Packet
* @param len the length of __buffer
* @param the index of device which receive the packet.
* @return 0 on success, 1 on failure.
*/
int egIPCallback(const void* __buffer, const struct IPHeader header, int len, int index){
    char* buffer = (char*) __buffer;
    printf("Call egIPCallback()\n");
    printf("proto type: %04x\n", header.protocol);
    printf("Source IP address:");  printip(header.src_addr);
    puts("");

    printf("Destination IP address:"); printip(header.dst_addr);
    puts("");

    printf("Packet identification: %u\n", header.identification);
    for (int i = 0; i < len; i++){
        printf("%02x ",(unsigned char)(buffer[i]));
        if ((i + 1) % BYTE_IN_ROW == 0)
            puts("");
    }
    puts("");
    puts("");
    return 0;
}

#endif