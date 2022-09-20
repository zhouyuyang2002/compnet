

/* *
* @file packetio . h
* @brief Library supporting sending / receiving Ethernet II frames .
*/
#ifndef PACKETIO_H
#define PACKETIO_H
#include "device.h"
#include "debug.h"
#include <netinet/ether.h>
#include <arpa/inet.h>
/* *
* @brief Encapsulate some data into an Ethernet II frame and send it .
*
* @param buf Pointer to the payload .
* @param len Length of the payload .
* @param ethtype EtherType field value of this frame .
* @param destmac MAC address of the destination .
* @param id ID of the device ( returned by "addDevice") to send on .
* @return 0 on success , -1 on error .
* @see addDevice
*/
int sendFrame (const void * buf, int len, 
int ethtype, const void *destmac, int id){
    if (id < 0 || id >= d_manager.count())
        errhandle("Illegal decive index\n");
    DeviceNode* device = d_manager[id];
    if (device->send_handler == NULL)
        errhandle("send handler does not exist\n");
    struct ethhdr framehdr;
    memcpy(framehdr.h_dest, destmac, sizeof(uint8_t) * 6);
    memcpy(framehdr.h_source, device->mac_addr, sizeof(uint8_t) * 6);
    framehdr.h_proto = (uint16_t)htons(ethtype);

    u_char* framebuf = new u_char[len + sizethhdr];
    memcpy(framebuf + sizethhdr, buf, sizeof(u_char) * len);
    memcpy(framebuf, &framehdr, sizeof(u_char) * sizethhdr);

    printf("Try to send buffer with size: %d\n", len + sizethhdr);
    for (int i = 0; i < len + sizethhdr; i++){
        printf("%02x ", (unsigned char)framebuf[i]);
        if (i % 16 == 15) puts("");
    }
    puts("");
    puts("");

    if (pcap_sendpacket(device->send_handler, framebuf, len + sizethhdr) != 0){
        delete[] framebuf;
        errhandle("failed to send the ethernet packet\n");
    }
    delete[] framebuf;
    return 0;
}
/* *
* @brief Register a callback function to be called each time an
*
Ethernet II frame was received .
*
* @param callback the callback function .




* @return 0 on success , -1 on error .
* @see f r a m e R e c e i v e C a l l b a c k
*/

int setFrameReceiveCallback(frameReceiveCallback callback, int id){
    if (id < 0 || id >= d_manager.count())
        errhandle("Illegal decive index\n");
    DeviceNode* device = d_manager[id];
    if (device->send_handler == NULL)
        errhandle("send handler does not exist\n");
    device->setCallback(callback);
    return 0;
}

int receiveAllFrame(int id, int frame_count){
    if (id < 0 || id >= d_manager.count())
        errhandle("Illegal decive index\n");
    DeviceNode* device = d_manager[id];
    if (device->receive_handler == NULL)
        errhandle("reveice handler does not exist\n");
    if (frame_count < -1)
        errhandle("Illegal frame_count");
    struct pcap_pkthdr* pkt_header = NULL;
    const u_char* framebuf = NULL;

    #define checkrem(); if (frame_count > 0)\
        fprintf(stderr, "%d packets remain unrecieved", frame_count);
    while (true){
        int result = pcap_next_ex(device->receive_handler, &pkt_header, &framebuf);
        if (result == 0){
            checkrem();
            errhandle("Time out");
        }
        if (result == -1){
            checkrem();
            errhandle("error, pcap_next_ex(): %s", pcap_geterr(device->receive_handler));
        }
        if (result == -2){
            checkrem();
            break;
        }
        device->handInPacket(pkt_header, framebuf);
        if (frame_count != -1)
            if ((--frame_count) == 0)
                break;
    }
    #undef checkrem();
    return 0;
}


#endif 