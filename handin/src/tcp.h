#ifndef MYTCP_H
#define MYTCP_H

#include "ip.h"
#include "type.h"
#include <string.h>

int sendTCPPacket(struct TCPHeader header, struct sockaddr_in src, struct sockaddr_in dst, void* buf, size_t len){
    //printf("Try to send TCP Packet !!!\n");
    struct TCPPseudoHeader pseudo_header;
    header.syn_num = htonl(header.syn_num);
    header.ack_num = htonl(header.ack_num);
    header.src_port = htons(src.sin_port);
    header.dst_port = htons(dst.sin_port);
    header.window = htons(WNDVAL);
    header.offset = 6;
    pseudo_header.src_addr.s_addr = htonl(src.sin_addr.s_addr);
    pseudo_header.dst_addr.s_addr = htonl(dst.sin_addr.s_addr);
    pseudo_header.zero = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.length = htons(len + sizeof(header));
    /*for (int i = 0; i < 24 ; i++)
        printf("%02x ", ((unsigned char*)&header)[i]); puts("");
    for (int i = 0; i < 12 ; i++)
        printf("%02x ", ((unsigned char*)&pseudo_header)[i]); puts("");*/
    header.CalcCheckSum(pseudo_header);

    int packet_len = len + sizeof(header);
    char* buffer = new char[packet_len + 5];
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, &header, sizeof(header));
    if (len != 0)
        memcpy(buffer + sizeof(header), buf, len);
    int result = sendIPPacket(src.sin_addr, dst.sin_addr, IPPROTO_TCP, buffer, packet_len);
    delete[] buffer;
    return result;
}
#endif

