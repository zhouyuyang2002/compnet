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
#include "portmanager.h"
#include "portal.h"
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

int IPCallback(const void* __buffer, const struct IPHeader header, int len, int index){
    char* buffer = (char*) __buffer;
    if (header.protocol == TCPPROTOCOL){
        struct TCPPseudoHeader Pseudo_header;
        if (len < sizeof(struct TCPHeader))
            errhandle("Invalid packet header");
        Pseudo_header.src_addr.s_addr = htonl(header.src_addr.s_addr);
        Pseudo_header.dst_addr.s_addr = htonl(header.dst_addr.s_addr);
        Pseudo_header.zero = 0;
        Pseudo_header.protocol = TCPPROTOCOL;
        Pseudo_header.length = htons(len);
        struct TCPHeader TCP_header = *((struct TCPHeader*) buffer);
        /*for (int i = 0; i < 24 ; i++)
            printf("%02x ", ((unsigned char*)&TCP_header)[i]); puts("");
        for (int i = 0; i < 12 ; i++)
            printf("%02x ", ((unsigned char*)&Pseudo_header)[i]); puts("");*/
        if (TCP_header.CheckValid(Pseudo_header) == -1)
            errhandle("Invalid packet checksum");
        struct sockaddr_in sock;
        sock.sin_addr = header.dst_addr;
        sock.sin_port = ntohs(TCP_header.dst_port);
        sock.sin_family = AF_INET;
        int port_index = port_manager[sock];
        if (port_index == -1)
            errhandle("Invalid socket address");
        TCP_header.syn_num = htonl(TCP_header.syn_num);
        TCP_header.ack_num = htonl(TCP_header.ack_num);
        TCP_header.src_port = htons(TCP_header.src_port);
        TCP_header.dst_port = htons(TCP_header.dst_port);
        TCP_header.window = htons(TCP_header.window);
        return socket_manager[port_index]->packetHandle(header, TCP_header, buffer + sizeof(struct TCPHeader), len - sizeof(struct TCPHeader));
    }
    else{
        printf("unknown packet type(not a TCP Packet)");
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
}

#endif