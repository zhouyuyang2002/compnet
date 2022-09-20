/* *
* @file device . h
* @brief Library supporting network device management .
*/

#ifndef DEVICE_H
#define DEVICE_H
#include <pcap/pcap.h>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <vector>
#include "name2mac.h"
#include "debug.h"

/* *
* Check whether the device name exists in the network.
*
* @param device Name of network device to check
* @return True on success , False on error .
*/
bool checkDevice(const char * device){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *it;

    int result;
    result = pcap_findalldevs(&alldevs, errbuf);
    if (result == -1){
        fprintf(stderr, "err: %s\n",errbuf);
        pcap_freealldevs(alldevs);
        return false;
    }

    for (it = alldevs; it != NULL; it = it->next)
        if (strcmp(device, it->name) == 0){
            pcap_freealldevs(alldevs);
            return true;
        }
    
    pcap_freealldevs(alldevs);
    return false;
}

struct DeviceNode{
    char* device_names;
    pcap_t* receive_handler;
    pcap_t* send_handler;
    frameReceiveCallback callback;
    uint8_t mac_addr[8];
    int index;
    
    DeviceNode(){
        device_names = 0;
        receive_handler = NULL;
        send_handler = NULL;
        callback = NULL;
    }
    ~DeviceNode(){
        if (device_names != NULL)
            delete[] device_names;
        if (receive_handler != NULL)
            pcap_close(receive_handler);
        if (send_handler != NULL)
            pcap_close(send_handler);
    }

    bool isEqualDevice(const char* device){
        return strcmp(device, device_names) == 0;
    }
    
    void setCallback(frameReceiveCallback __callback__){
        callback = __callback__;
    }
    int setDevice(const char* device){

        char errbuf[PCAP_ERRBUF_SIZE];
        int len = strlen(device);
        device_names = new char[len + 1];
        strcpy(device_names, device);

        send_handler = pcap_create(device_names, errbuf);
        if (send_handler == NULL)
            errhandle("fail to create a send_handler, err: %s\n", errbuf);
        if (pcap_activate(send_handler) < 0)
            errhandle("fail to activate a send_handler, err: %s\n", pcap_geterr(send_handler));
        if (pcap_setdirection(send_handler, PCAP_D_OUT) != 0)
            errhandle("fail to set a handler\n");

        receive_handler = pcap_create(device_names, errbuf);
        if (receive_handler == NULL)
            errhandle("fail to create a send_handler, err: %s\n", errbuf);
        if (pcap_activate(receive_handler) < 0)
            errhandle("fail to activate a send_handler, err: %s\n", pcap_geterr(send_handler));
        if (pcap_setdirection(receive_handler, PCAP_D_IN) != 0)
            errhandle("fail to set a send_handler\n");

        if (findMac(device, mac_addr) == -1)
            errhandle("fail to find mac address in setDevice()\n");
        return 0;
    }

    int handInPacket(struct pcap_pkthdr* pkt_header, const u_char* framebuf){
        if (callback == NULL){
            printf("Warning: you have not set callback!");
            printf("Capture Package size: %d\n",pkt_header->caplen);
            printf("Capture Package on Device: %s\n", device_names);
            printf("Device Mac Address %02x:%02x:%02x:%02x:%02x:%02x\n", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
            for (int i = 0; i < pkt_header->caplen; i++){
                printf("%02x ", framebuf[i]);
                if ((i + 1) % BYTE_IN_ROW == 0) puts("");
            }
            puts("");
            puts("");
        }
        else{
            const uint8_t* src_mac = framebuf;
            const u_char* buffer = framebuf + sizethhdr;
            callback(buffer, src_mac, pkt_header->caplen - sizethhdr, index);
        }

        return 0;
    }
};

struct DeviceManager{
    DeviceNode** device_list;
    int device_count;
    int device_bound;

    DeviceManager(){
        device_count = 0;
        device_bound = 0;
        device_list = NULL;
    }
    ~DeviceManager(){
        for (int i = 0; i < device_count; i++)
            delete device_list[i];
        delete[] device_list;
    }

    DeviceNode* operator [](const int index){
        if (index < 0 || index > device_count){
            fprintf(stderr, "Invalid index in deviceManager");
            return NULL;
        }
        return device_list[index];
    }

    int addDevice(const char* device){
        if (checkDevice(device) == -1)
            errhandle("Invalid device name");
        if (device_bound == device_count){
            device_bound = device_bound * 2 + 1;
            DeviceNode** new_device_list = new DeviceNode*[device_bound];
            memset(new_device_list, (int)NULL, sizeof(DeviceNode*) * device_bound);
            memcpy(new_device_list, device_list, sizeof(DeviceNode*) * device_count);
            delete[] device_list;
            device_list = new_device_list;
        }
        int index = device_count++;
        device_list[index] = new DeviceNode();
        if (device_list[index]->setDevice(device) == -1){
            --device_count;
            delete device_list[index];
            device_list[index] = NULL;
            errhandle("Failed to setDevice\n");
        }
        else
            device_list[index]->index = index;
        return index;
    }

    int findDevice(const char* device){
        for (int i = 0; i < device_count; i++)
            if (device_list[i]->isEqualDevice(device))
                return i;
        return -1;
    }

    int count(){
        return device_count;
    }

}d_manager;

/* *
* Add a device to the library for sending / receiving packets .
*
* @param device Name of network device to send / receive packet on .
* @return A non - negative _device - ID_ on success , -1 on error .
*/
int addDevice ( const char * device ){
    return d_manager.addDevice(device);
}
/* *
* Find a device added by ‘ addDevice ‘.
*
* @param device Name of the network device .
* @return A non - negative _device - ID_ on success , -1 if no such device
* was found .
*/
int findDevice ( const char * device ){
    return d_manager.findDevice(device);
}

#endif