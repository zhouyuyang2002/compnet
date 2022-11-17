#include "device.h"
#include "packetio.h"
#include "name2addr.h"
#include "callback.h"
#include "ip.h"
#include <signal.h>

#include <pcap/pcap.h>

//Wrapped Linklayer callback function
int wrappedLinkCallback(const void* __buffer, const void* __mac_addr, int len, int index, uint16_t proto){
    return LinkCallback(__buffer,__mac_addr,len, index, proto);
}

//Wrapped IPlayer callback function
int wrappedIPCallback(const void* __buffer, const IPHeader header, int len, int index){
    return egIPCallback(__buffer, header, len, index);
}

int main(int argc, char** argv){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *it;

    int result;
    result = pcap_findalldevs(&alldevs, errbuf);  
    uint8_t mac_addr[8];
    struct in_addr ip_addr;
    for (it = alldevs; it != NULL; it = it->next){
        //printf("Device %s, description (%s), MAC address:", it->name, it->description);
        bool tag = true;
        if (findMac(it->name, mac_addr) == -1) tag = false;
        if (findIP(it->name, ip_addr) == -1) tag = false;
        if (tag == true)
            addDevice(it->name);
    }

	for (int i = 0; i < d_manager.count(); i++){
        setFrameReceiveCallback(wrappedLinkCallback, i);
        setIPPacketReceiveCallback(wrappedIPCallback, i);
    }
    while (true)
        for (int i = 0; i < d_manager.count(); i++)
            receiveAllFrame(i, 5);

    // it should not reach this...
    return 0;
}