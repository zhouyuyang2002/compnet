#include "device.h"
#include "packetio.h"
#include "name2addr.h"
#include "callback.h"
#include "ip.h"
#include <signal.h>

#include <pcap/pcap.h>

const char msg[] = "1145141919810 19260817 998244353 1000000007 chick you are so beauty";

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
        if (findMac(it->name, mac_addr) != -1){
            //printmac(mac_addr);
        }
        else{
            //printf("not found");
            tag = false;
        }
        //printf(" IP address:");

        if (findIP(it->name, ip_addr) != -1){
            //printip(ip_addr);
        }
        else{
            //printf("not found");
            tag = false;
        }

        //puts("");
        if (tag == true)
            addDevice(it->name);
    }

    struct in_addr IPAddr[10];
    IPAddr[1] = (struct in_addr){0x0a640101};
    IPAddr[2] = (struct in_addr){0x0a640201};
    IPAddr[3] = (struct in_addr){0x0a640301};
    IPAddr[4] = (struct in_addr){0x0a640302};
    IPAddr[5] = (struct in_addr){0x0a640601};
    IPAddr[6] = (struct in_addr){0x0a640602};

	// ns1 -- ns2 -- ns3 -- ns4
	// transmit a packet to each device
    if (atoi(argv[1]) == 1){
        int index = -1;
        if (strcmp(argv[2], "ns4") == 0) index = 4;
        if (strcmp(argv[2], "ns3") == 0) index = 3;
        if (strcmp(argv[2], "ns2") == 0) index = 2;
        if (strcmp(argv[2], "ns1") == 0) index = 1;
        if (index == -1) return 0;
        for (int i = 0; i < d_manager.count(); i++){
            setFrameReceiveCallback(wrappedLinkCallback, i);
            setIPPacketReceiveCallback(wrappedIPCallback, i);
        }
        long long tic = gettime();
        printf("current tic = %lld\n", (long long) tic);
        tic = tic + (30000000 - tic % 30000000);
        if (index != 1) tic = tic + 20000000;
        if (index == 1) tic = tic + 10000000;
        printf("send tic = %lld\n", (long long) tic);
        while (true){
            for (int i = 0; i < d_manager.count(); i++)
                receiveAllFrame(i, 5);
            if (gettime() > tic){
                printf("ready to send on device ns%d\n", index);
                for (int i = 1; i <= 4; i++)
                    if (i != index) sendIPPacket(IPAddr[index], IPAddr[i], 0x17, msg, strlen(msg));
                tic = 0x7fffffffffffffffll;
            }
        }
    }

	// Connection test, CP4
    if (atoi(argv[1]) == 2){
        int index = -1;
        if (strcmp(argv[2], "ns4") == 0) index = 4;
        if (strcmp(argv[2], "ns3") == 0) index = 3;
        if (strcmp(argv[2], "ns2") == 0) index = 2;
        if (strcmp(argv[2], "ns1") == 0) index = 1;
        if (index == -1) return 0;
        for (int i = 0; i < d_manager.count(); i++){
            setFrameReceiveCallback(wrappedLinkCallback, i);
            setIPPacketReceiveCallback(wrappedIPCallback, i);
        }
        if (index == 1){
            long long tic = gettime();
            for (;;){
                if (gettime() > tic){
                    tic = 0x7fffffffffffffff;
                    if (sendIPPacket(IPAddr[1], IPAddr[4], 0x17, msg, strlen(msg)) == -1)
                        printf("Warning: Disconnected\n");
                }
                for (int i = 0; i < d_manager.count(); i++)
                    receiveAllFrame(i, 5);
            }
        }
        else{
            while (true)
                for (int i = 0; i < d_manager.count(); i++)
                    receiveAllFrame(i, 5);
        }
        return 0;
    }

	// longest routing rule test
    if (atoi(argv[1]) == 3){
        int index = -1;
        if (strcmp(argv[2], "ns4") == 0) index = 4;
        if (strcmp(argv[2], "ns3") == 0) index = 3;
        if (strcmp(argv[2], "ns2") == 0) index = 2;
        if (strcmp(argv[2], "ns1") == 0) index = 1;
        if (index != 1) return 0;

        struct in_addr fmask16 = (struct in_addr){0xffff0000};
        struct in_addr fmask24 = (struct in_addr){0xffffff00};
        struct in_addr dest_A = (struct in_addr){0x12345678};
        struct in_addr dest_B = (struct in_addr){0x1234abcd};
        struct macAddress value1, value2;
        value1.m_addr[0] = 0x12;
        value2.m_addr[0] = 0x34;
        for (int i = 1; i <= 5; i++)
            value1.m_addr[i] = value2.m_addr[i] = 0;
        setRoutingTable(dest_A, fmask16, &value1, d_manager[0] -> device_names);
        printf("Set Routing Rule, dest: "); printip(dest_A);
        printf(", mask: "); printip(fmask16);
        printf(", nextHopMac: "); printmac(value1);
        puts("");

        setRoutingTable(dest_B, fmask24, &value2, d_manager[0] -> device_names);
        printf("Set Routing Rule, dest: "); printip(dest_B);
        printf(", mask: "); printip(fmask24);
        printf(", nextHopMac: "); printmac(value2);
        puts("");

        struct macAddress result;
        int result_index;
        puts("");
        if (getNextHopMac(dest_A, &result, result_index) != 0)
            printf("failed to find the nextHopMac!");
        else{
            printf("destination: "); printip(dest_A);
            printf(",nextHopMac found: "); printmac(result);
            puts("");
        }
        if (getNextHopMac(dest_B, &result, result_index) != 0)
            printf("failed to find the nextHopMac!");
        else{
            printf("destination: "); printip(dest_B);
            printf(",nextHopMac found: "); printmac(result);
            puts("");
        }
        return 0;
    }

	// 6 device routing distance test
    if (atoi(argv[1]) == 4){
        int index = -1;
        if (strcmp(argv[2], "ns6") == 0) index = 6;
        if (strcmp(argv[2], "ns5") == 0) index = 5;
        if (strcmp(argv[2], "ns4") == 0) index = 4;
        if (strcmp(argv[2], "ns3") == 0) index = 3;
        if (strcmp(argv[2], "ns2") == 0) index = 2;
        if (strcmp(argv[2], "ns1") == 0) index = 1;
        if (index == -1) return 0;
        for (int i = 0; i < d_manager.count(); i++){
            setFrameReceiveCallback(wrappedLinkCallback, i);
            setIPPacketReceiveCallback(wrappedIPCallback, i);
        }
        long long tic = gettime();
        printf("current tic = %lld\n", (long long) tic);
        tic = (tic + 20000000) + (3000000 - (tic + 20000000) % 3000000) + index * 5000000;
        printf("send tic = %lld\n", (long long) tic);
        while (true){
            for (int i = 0; i < d_manager.count(); i++)
                receiveAllFrame(i, 5);
            if (gettime() > tic){
                tic = 0x7fffffffffffffffll;
                for (int i = 1; i <= 6; i++)
                    if (i != index){
                        macAddress mac;
                        int useless;
                        getNextHopMac(IPAddr[i], &mac, useless);
                    }
                printf("distance table: [");
                for (int i = 1; i <= 6; i++){
                    if (i != index) {
                        if (distance.find(IPAddr[i].s_addr) == 0)
                            printf("-1");
                        else 
                            printf("%d", distance[IPAddr[i].s_addr]);
                    }
                    else printf("0");
                    if (i == 6) printf("]\n");
                    else printf(", ");
                }
            }
        }
    }
}