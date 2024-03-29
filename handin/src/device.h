/* *
* @file device.cpp
* @brief Library supporting network device management .
*/

#ifndef DEVICE_H
#define DEVICE_H
#include <pcap/pcap.h>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <vector>
#include "type.h"
#include "macro.h"
#include "constant.h"
#include "name2addr.h"
#include "iptable.h"
#include "routing.h"

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
    char* device_names;                  //The name of device 
    pcap_t* receive_handler;             //The handler used to receive messages
    pcap_t* send_handler;                //The handler used to send messages
    frameReceiveCallback callback;       //The default Link Layer callback function
    IPPacketReceiveCallback ip_callback; //The default IP Layer callback function
    uint8_t mac_addr[8];                 //Mac address of the device
    struct in_addr ip_addr;              //IP address of the device
    int index;                           //The index of the device
    
    DeviceNode(){
        device_names = 0;
        receive_handler = NULL;
        send_handler = NULL;
        ip_callback = NULL;
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

    /* *
    * Check if the name of the device is equal to device
    * @param device The name of device to check out
    * @return True on same, False on different
    */
    bool isEqualDevice(const char* device){
        return strcmp(device, device_names) == 0;
    }

    bool isEqualIP(const in_addr ip){
        return ip_addr.s_addr == ip.s_addr;
    }
    /* *
    * Set up the callback function of the device
    * @param __callback__ the name of __callback__ function to set up
    */
    void setCallback(frameReceiveCallback __callback__){
        callback = __callback__;
    }
     /* *
    * Set up the callback function of the device
    * @param __callback__ the name of __callback__ function to set up
    */
    void setIPCallback(IPPacketReceiveCallback __callback__){
        ip_callback = __callback__;
    }


    /* *
    * Initalize the deviceNode with name device
    * @param device The name of device used to set up
    * @return 0 on success, -1 on failure. 
    */
    int setDevice(const char* device){

        char errbuf[PCAP_ERRBUF_SIZE];
        int len = strlen(device);
        device_names = new char[len + 1];
        strcpy(device_names, device);

        if (findMac(device, mac_addr) == -1)
            errhandle("fail to find mac address in setDevice()\n");
        if (findIP(device, ip_addr) == -1)
            errhandle("fail to find ip address in setDevice()\n");

        send_handler = pcap_create(device_names, errbuf);
        if (send_handler == NULL)
            errhandle("fail to create a send_handler, err: %s\n", errbuf);
        if (pcap_activate(send_handler) < 0)
            errhandle("fail to activate a send_handler, err: %s\n", pcap_geterr(send_handler));
        if (pcap_setdirection(send_handler, PCAP_D_OUT) != 0)
            errhandle("fail to set a handler\n");

        receive_handler = pcap_create(device_names, errbuf);
        if (receive_handler == NULL)
            errhandle("fail to create a receive_handler, err: %s\n", errbuf);
       
        if (pcap_setnonblock(receive_handler, true, errbuf) != 0)
            errhandle("fail to set non-block type of receive_handler, err: %s\n", errbuf);        
        if (pcap_set_timeout(receive_handler, 10) != 0)
            errhandle("fail to set time-out");
        if (pcap_activate(receive_handler) < 0)
            errhandle("fail to activate a receive_handler, err: %s\n", pcap_geterr(send_handler)); 
            
        char compilebuf[COMPILEBUF_SIZE];
        memset(compilebuf, 0, sizeof(compilebuf));
        sprintf(compilebuf, "ether dst %02x:%02x:%02x:%02x:%02x:%02x or ether dst ff:ff:ff:ff:ff:ff", 
                (unsigned char)mac_addr[0], (unsigned char)mac_addr[1], (unsigned char)mac_addr[2],
                (unsigned char)mac_addr[3], (unsigned char)mac_addr[4], (unsigned char)mac_addr[5]);
        //printf("%s\n", compilebuf);
        struct bpf_program fp;
        if (pcap_compile(receive_handler, &fp, compilebuf, 0, PCAP_NETMASK_UNKNOWN) != 0)   
            errhandle("fail to compile the filter, err: %s\n", pcap_geterr(receive_handler));
        if (pcap_setfilter(receive_handler, &fp) != 0)
            errhandle("fail to set the filter, err: %s\n", pcap_geterr(receive_handler));
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
    /* *
    * Return the pointer of the index-th DeviceNode
    * @param index The index of device to find
    */
    DeviceNode* operator [](const int index){
        if (index < 0 || index > device_count){
            fprintf(stderr, "Invalid index in deviceManager");
            return NULL;
        }
        return device_list[index];
    }
    /* *
    * Add a device to the library for sending / receiving packets .
    *
    * @param device Name of network device to send / receive packet on .
    * @return A non - negative _device - ID_ on success , -1 on error .
    */
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
    /* *
    * Find a device added by ‘ addDevice ‘.
    *
    * @param device Name of the network device .
    * @return A non - negative _device - ID_ on success , -1 if no such device
    * was found .
    */
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