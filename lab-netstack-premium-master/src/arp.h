/* *
* @file arp.h
* @brief Library for my ARP-Like Routing algorithm.
*/

#ifndef MYARP_H
#define MYARP_H
#include "routing.h"
#include "packetio.h"
#include "device.h"
#include "type.h"
#include "macro.h"
#include "constant.h"
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/signal.h>

#define ARPREQUEST 0x01
#define ARPREPLY   0x02

/* *
* The callback function for my ARP-Like routing algorithm. The function is called
* if the device receive a ARP-Like packet.
* 
* @param __buffer the buffer of the ARP-Like Header
* @param mac_addr the device which send the ARP-Header to us
* @param len the length of the buffer
* @param index the index of the device which receive the ARP-Header.
* @return 0 on success, -1 on failure.
*/
int ARPCallback(const void* __buffer, const void* __mac_addr, int len, int index){
    struct macAddress src_mac = *((struct macAddress*) __mac_addr);
    /*printf("Receive ARP REQuest from ");
    printmac(src_mac.m_addr);
    puts("");*/

    if (len != sizeof(ARPHeader))
        errhandle("Bad ARP Packet : length");

    struct ARPHeader header = *((struct ARPHeader*)__buffer);
    if (header.h_type != htons(ETHERNET))
        errhandle("Bad ARP Packet : h_type");
    if (header.h_length != 6)
        errhandle("Bad ARP Packet : h_length");
    if (header.p_type != htons(IPPROTOCOL))
        errhandle("Bad ARP Packet : p_type");
    if (header.p_length != 4)
        errhandle("Bad ARP Packet : p_length");
    
    if (header.op_type == htons(ARPREQUEST)){
        uint32_t src = ntohl(header.src_ipaddr.s_addr);
        uint32_t dst = ntohl(header.dst_ipaddr.s_addr);
        //printf("request src: %08x, dst: %08x\n", src, dst);
        bool resend = false;
        if (info.find(src) == 0){
            info[src] = header.src_macaddr;
            distance[src] = ntohs(header.dist);
            routing.setNextHopMac(src, __full_mask, std::make_pair(src_mac, index));
            resend = true;
        }
        int ip_index = -1;
        for (int i = 0; i < d_manager.count(); i++)
            if (d_manager[i] -> ip_addr.s_addr == dst)
                ip_index = i;
        if (ip_index != -1){
            swap(header.dst_ipaddr, header.src_ipaddr);
            swap(header.dst_macaddr, header.src_macaddr);
            memcpy(&header.src_macaddr, d_manager[ip_index] -> mac_addr, sizeof(macAddress));
            header.op_type = htons(ARPREPLY);
            header.dist = htons(1);
            sendFrame(&header, sizeof(ARPHeader), ARPPROTOCOL, __mac_addr, index);
            resend = false;
        }
        else if (info.find(dst) == 1){
            swap(header.dst_ipaddr, header.src_ipaddr);
            swap(header.dst_macaddr, header.src_macaddr);
            header.src_macaddr = info[dst];
            header.op_type = htons(ARPREPLY);
            header.dist = htons(distance[dst] + 1);
            sendFrame(&header, sizeof(ARPHeader), ARPPROTOCOL, __mac_addr, index);
            resend = false;
        }
        else if (broadcast.find(dst) == false){
            resend = true;
        }
        if (resend){
            broadcast[dst] = true;
            header.dist = htons(ntohs(header.dist) + 1);
            for (int i = 0; i < d_manager.count(); i++)
                sendFrame(&header, sizeof(ARPHeader), ARPPROTOCOL, &__broadcast_addr, i);
        }
        return 0;
    }

    if (header.op_type == htons(ARPREPLY)){
        uint32_t src = ntohl(header.src_ipaddr.s_addr);
        uint32_t dst = ntohl(header.dst_ipaddr.s_addr);
        if (info.find(src) == 0){
            info[src] = header.src_macaddr;
            distance[src] = ntohs(header.dist);
            routing.setNextHopMac(src, __full_mask, std::make_pair(src_mac, index));
        }
        int index = -1;
        for (int i = 0; i < d_manager.count(); i++)
            if (d_manager[i] -> ip_addr.s_addr == dst)
                index = i;
        if (index != -1)
            return 0;
        if (info.find(dst) == 0)
            errhandle("ARP protocol error!");
        std::pair<macAddress, int> value;
        if (routing.queryNextHopMac(dst, &value) != 0)
            errhandle("ARP protocol error!");
        header.dist = htons(ntohs(header.dist) + 1);
        sendFrame(&header, sizeof(ARPHeader), ARPPROTOCOL, &value.first, value.second);
        return 0;
    }
    
    return -1;
}

bool pause_tag;
void sigalrmHandler(int signal){
    if (signal == SIGVTALRM)
        pause_tag = true;
}


/* *
* find the Mac address for the next HOP
* 
* @param dst_ipaddr the ip address of the device which packet will be send.
* @param nextHopMac the piece of memory to save the Mac address of the nextHop
* @param index      the index of device to retransmit the packet.
* @return 0 on success, -1 on failure.
*/
int getNextHopMac(struct in_addr dst_ipaddr, void* nextHopMac, int &index){
    uint32_t dst = dst_ipaddr.s_addr;
    for (int i = 0; i < d_manager.count(); i++){
        if (d_manager[i] -> ip_addr.s_addr == dst){
            memcpy(nextHopMac, d_manager[i] -> mac_addr, sizeof(macAddress));
            index = i;
            return 0;
        }
    }
    std::pair<macAddress, int> value;
    if (routing.queryNextHopMac(dst, &value) == 0){
        *((struct macAddress*)nextHopMac) = value.first;
        index = value.second;
        return 0;
    }

    struct ARPHeader header;
    header.h_type = htons(ETHERNET);   header.h_length = 6;
    header.p_type = htons(IPPROTOCOL); header.p_length = 4;
    header.op_type = htons(ARPREQUEST); header.dist = htons(1);
    for (int i = 0; i < d_manager.count(); i++){
        header.src_ipaddr.s_addr = htonl(d_manager[i] -> ip_addr.s_addr);
        header.dst_ipaddr.s_addr = htonl(dst_ipaddr.s_addr);
        memcpy(&header.src_macaddr, d_manager[i] -> mac_addr, sizeof(macAddress));
        header.op_type = htons(ARPREQUEST);
        sendFrame(&header, sizeof(struct ARPHeader), ARPPROTOCOL, &__broadcast_addr, i);
    }
    static bool firstcal = false;
    if (firstcal == false){
        firstcal = true;
        signal(SIGVTALRM, sigalrmHandler);
    }
    for (int i = 0; i < 8; i++){
        usleep(2500 << i);                   // sleep for (2500 << i) us;
        struct itimerval tic;
        tic.it_interval = (struct timeval){1000, 0};
        tic.it_value = (struct timeval){0, 50000};
        pause_tag = false;
        setitimer(ITIMER_VIRTUAL, &tic, NULL);
        for (pause_tag = false; !pause_tag; ){// spin for 50000 us
            for (int i = 0; i < d_manager.count(); i++)
                receiveAllFrame(i, 5);
            std::pair<macAddress, int> value;
            if (routing.queryNextHopMac(dst, &value) == 0){
                *((struct macAddress*)nextHopMac) = value.first;
                index = value.second;
                return 0;
            }
        }
        setitimer(ITIMER_VIRTUAL, NULL, NULL);
    }
    return -1;
}
#endif