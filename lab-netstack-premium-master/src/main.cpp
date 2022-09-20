#include "device.h"
#include "packetio.h"
#include "debug.h"

#include <pcap/pcap.h>

const char msg[] = "1145141919810 19260817 998244353 1000000007 chick you are so beauty";

int egCallback(const void* __buffer, const void* __mac_addr, int len, int index){
    u_char* buffer = (u_char*) __buffer;
    uint8_t* mac_addr = (uint8_t*) __mac_addr;
    printf("Call egCallBack()\n");
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

int main(){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *it;

    int result;
    result = pcap_findalldevs(&alldevs, errbuf);  
    uint8_t mac_addr[8];
    for (it = alldevs; it != NULL; it = it->next){
        printf("Device %s, description (%s), MAC address:", it->name, it->description);
        if (findMac(it->name, mac_addr) != -1){
            printmac(mac_addr);
            addDevice(it->name);
        }
        else
            printf("not found");
        puts("");
    }

    sendFrame(msg, strlen(msg), 0x0806, d_manager[0]->mac_addr, 0);
    setFrameReceiveCallback(egCallback, 0);
    sleep(1);
    receiveAllFrame(0, 5);
    return 0;
}