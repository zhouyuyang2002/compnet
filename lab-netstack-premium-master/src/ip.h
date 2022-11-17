/* *
* @file ip.h
* @brief Library supporting sending / receiving IP packets encapsulated
in an Ethernet II frame .
*/

#ifndef IP_H
#define IP_H
#include "type.h"
#include "macro.h"
#include "constant.h"
#include "device.h"
#include "arp.h"
#include <netinet/ip.h>
/* *
* @brief Send an IP packet to specified host .
*
* @param src Source IP address .
* @param dest Destination IP address .
* @param proto Value of ‘ protocol ‘ field in IP header .
* @param buf pointer to IP payload
* @param len Length of IP payload
* @return 0 on success , -1 on error .
*/

int sendIPPacket(const struct in_addr src ,const struct in_addr dest ,
                int proto , const void * buf , int len){
    int index = 0;
    struct macAddress nextHopMac;
    if (getNextHopMac(dest, &nextHopMac, index) != 0)
        errhandle("Failed to find the nextHopMac, Disconnected!");

    static int identification = 0;
    struct IPHeader header;
    header.version = 4;
    header.IHL = 5;
    header.TofService = 0x00;//magic
    header.length = htons(len + header.IHL * 4);
    header.identification = htons(identification++);
    header.flags = NO_FRAG | LAST_FRAG;
    header.time2live = 0x40;
    header.protocol = (unsigned char)proto;
    header.src_addr.s_addr = htonl(src.s_addr);
    header.dst_addr.s_addr = htonl(dest.s_addr);
    header.CalcCheckSum();

    int headerlen = header.IHL * 4;
    int packetlen = len + headerlen;
    char* buffer = new char[packetlen];
    memcpy(buffer, &header, (size_t) headerlen);
    memcpy(buffer + headerlen, buf, (size_t) len);
    sendFrame(buffer, packetlen, IPPROTOCOL, &nextHopMac, index);
    return 0;
}
/* *
* @brief Register a callback function to be called each time an IP
packet was received .
*
* @param callback The callback function .
* @return 0 on success , -1 on error .
*/
void setIPPacketReceiveCallback(IPPacketReceiveCallback callback, int index){
    d_manager[index]->setIPCallback(callback);
}

/* *
* @brief Handle the IPPacket, retransmit it if the destination of the packet is not the device,
and call the callback function if it is the destination
*
* @param __buffer raw IPPacket including information and header
* @param len the length of __buffer .
* @return 0 on success , -1 on error .
*/
int IPHandInPacket(const void* __buffer, int len){

    struct IPHeader header = *((struct IPHeader*) __buffer);
    if (!header.CheckValid())
        errhandle("Bad IP header checksum");
    header.src_addr.s_addr = ntohl(header.src_addr.s_addr);
    header.dst_addr.s_addr = ntohl(header.dst_addr.s_addr);
    header.identification = ntohs(header.identification);
    header.length = htons(header.length);

    if (len != header.length)
        errhandle("Unmatched datagram length!\n");
    char* buffer = (char*)__buffer;

    int headerlen = 4 * header.IHL;
    int packetlen = len - headerlen;
    if (packetlen < 0)
        errhandle("packet length smaller than 0\n");
    int index = -1;
    for (int i = 0; i < d_manager.count(); i++)
        if (header.dst_addr.s_addr == d_manager[i] -> ip_addr.s_addr)
            index = i;
    if (index != -1){
        if (d_manager[index] -> ip_callback == NULL){
            printf("Warning: you have not set ip-layer callback!\n");
            printf("Capture IP Package size: %d\n", len);
            printf("Capture IP Package on Device: %s\n", d_manager[index] -> device_names);
            printf("Device IP Address: ");
            printip(d_manager[index] -> ip_addr);
            puts("");
            printf("PacketHeader:\n");
            for (int i = 0; i < headerlen; i++)
                printf("%02x%c", (unsigned char)*(((char *)__buffer) + i), i % 4 == 3?'\n':' ');
            printf("PacketInfo, length %d\n", packetlen);
            for (int i = 0; i < packetlen; i++){
                printf("%02x ", buffer[i + headerlen]);
                if ((i + 1) % BYTE_IN_ROW == 0) puts("");
            }
            puts("");
        }
        else{
            d_manager[index] -> ip_callback(buffer + headerlen, header, packetlen, index);
        }
        return 0;
    }
    else{
        int sender_index = 0;
        struct macAddress nextHopMac;
        if (getNextHopMac(header.dst_addr, &nextHopMac, sender_index) == -1)
            errhandle("Connection failed!");
        sendFrame(__buffer, len, IPPROTOCOL, &nextHopMac, sender_index);
        return 0;
    }
}


/* *
* @brief Manully add an item to routing table . Useful when talking
with real Linux machines .
*
* @param dest The destination IP prefix .
* @param mask The subnet mask of the destination IP prefix .
* @param nextHopMAC MAC address of the next hop .
* @param device Name of device to send packets on .
* @return 0 on success , -1 on error
*/
int setRoutingTable(const struct in_addr dest, const struct in_addr mask,
                    const void* nextHopMac, const char* device){
    int index = -1;
    for (int i = 0; i < d_manager.count(); i++)
        if (d_manager[i] -> isEqualDevice(device))
            index = i;
    if (index == -1)
        errhandle("cannot find the device");
    std::pair<macAddress, int> value;
    value.first = *((struct macAddress*)nextHopMac);
    value.second = index;
    routing.setNextHopMac(dest.s_addr, mask, value);
    return 0;
}
#endif