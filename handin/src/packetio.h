/* *
* @file packetio . h
* @brief Library supporting sending / receiving Ethernet II frames .
*/

#ifndef PACKETIO_H
#define PACKETIO_H

#include "mytime.h"
#include "device.h"
#include "constant.h"
#include "macro.h"
#include "type.h"
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
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
    
    /*printf("Try to send buffer with size: %d, tic = %lld\n", len + sizethhdr, (long long)gettime());
    for (int i = 0; i < len + sizethhdr; i++){
        printf("%02x ", (unsigned char)framebuf[i]);
        if (i % 16 == 15) puts("");
    }
    puts("");
    puts("");*/
    

    if (pcap_sendpacket(device->send_handler, framebuf, len + sizethhdr) != 0){
        delete[] framebuf;
        fprintf(stderr, "error %s\n", pcap_geterr(device->send_handler));
        fprintf(stderr, "buffer:\n");
        for (int i = 0; i < len + sizethhdr; i++){

            fprintf(stderr, "%02x ", (unsigned char)framebuf[i]);
            if (i % 16 == 15)
                puts("");
        }
        puts("");
        errhandle("failed to send the ethernet packet\n");

    }
    delete[] framebuf;
    return 0;
}

/* *
* @brief Register a callback function to be called each time an
* Ethernet II frame was received .
*
* @param callback the callback function.
* @return 0 on success , -1 on error.
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

/* *
* @brief After receive a packet captureed on specific device, try to handle it
* using the default function, and print the raw message if the function is not found.
*
* @param pkt_header the header of the packet captured.
* @param framebuf the buffer of the packet captured.
* @param index the index of the packet captured.
* @return 0 on success , -1 on error.
*/
int LinkHandInPacket(struct pcap_pkthdr* pkt_header, const u_char* framebuf, int index){
    if (d_manager[index] -> callback == NULL){
        printf("Warning: you have not set link-layer callback!");
        printf("Capture Package size: %d\n",pkt_header->caplen);
        printf("Capture Package on Device: %s\n", d_manager[index] ->device_names);
        printf("Device Mac Address: ");
        printmac(d_manager[index] -> mac_addr);
        puts("");
        for (int i = 0; i < pkt_header->caplen; i++){
            printf("%02x ", framebuf[i]);
            if ((i + 1) % BYTE_IN_ROW == 0) puts("");
        }
        puts("");
        puts("");
        }
    else{
        struct ethhdr framehdr = *((struct ethhdr*)framebuf);
        bool ignore = false;
        for (int i = 0; i < d_manager.count(); i++)
            {
                bool same = true;
                for (int j = 0; j < 6; j++)
                    if (d_manager[i] -> mac_addr[j] != framehdr.h_source[j])
                        same = false;
                if (same == true)
                    ignore = true;
            }
        if (ignore){
            //puts("ignored");
            return 0;
        }
        /*printf("Capture Package size: %d\n",pkt_header->caplen);
        printf("Capture Package on Device: %s\n", d_manager[index] ->device_names);
        printf("Device Mac Address: ");
        printmac(d_manager[index] -> mac_addr);
        puts("");
        for (int i = 0; i < pkt_header->caplen; i++){
            printf("%02x ", framebuf[i]);
            if ((i + 1) % BYTE_IN_ROW == 0) puts("");
        }
        puts("");*/
        const uint8_t* src_mac = framehdr.h_source;
        const u_char* buffer = framebuf + sizethhdr;
        uint16_t protocol = ntohs(framehdr.h_proto);
        d_manager[index] -> callback(buffer, src_mac, pkt_header->caplen - sizethhdr, index, protocol);
    }
    return 0;
}
/* *
* @brief try to receive specific number of Ethernet frames from device ID id.
*
* @param id The Index of device to receive the package.
* @param frame_count A number,-1 represents receiving until error occurs,
* 0-65535 represents the number of packet expected to receive.
* @return the number of packages received,
*/
int receiveAllFrame(int id, int frame_count){
    if (id < -1 || id >= d_manager.count())
        errhandle("Illegal decive index\n");
    DeviceNode* device = d_manager[id];
    if (device->receive_handler == NULL)
        errhandle("reveice handler does not exist\n");
    if (frame_count < -1)
        errhandle("Illegal frame_count");
    struct pcap_pkthdr* pkt_header = NULL;
    const u_char* framebuf = NULL;
    int num_received = 0;

    while (true){
        //printf("tic try to receive: %lld\n", gettime());
        int result = pcap_next_ex(device->receive_handler, &pkt_header, &framebuf);
        if (result == 0) // None of the package received
            return num_received;
        //printf("tic receive success: %lld\n", (long long)gettime());
        if (result < 0){
            fprintf(stderr, "error after receiving %d packets\n, pcap_next_ex(): %s", 
                            num_received, pcap_geterr(device->receive_handler));
            return num_received;
        }
        ++num_received;
        LinkHandInPacket(pkt_header, framebuf, id);
        if (frame_count != -1)
            if ((--frame_count) == 0)
                break;
    }
    return num_received;
}


#endif 