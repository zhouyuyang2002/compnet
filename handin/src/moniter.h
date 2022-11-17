
#ifndef MYMONITER_H
#define MYMONITER_H
#include "mytime.h"
#include "device.h"
#include "packetio.h"
#include "callback.h"
#include <pthread.h>
#include <signal.h>

int pid;
bool fin_initialize = false;
bool fin_sigint = false;
bool child_proc = true;
pthread_t tid;

const int RECEIVE_GAP = 5000; // 5 miliseconds
const int RETRANS_GAP = 20 * RECEIVE_GAP; // 100 miliseconds
// THis means that if we doesn't receive RETRANS_GAP after 6.4s,, we'll drop it.


void SIGINT_handler(int p_sig){
    printf("receive SIGINT on process %08x\n",(int)pthread_self());
    fin_sigint = true;
    for (;child_proc;);
    printf("parent process fin\n");
    printf("%d\n",d_manager.count());
    printf("%d\n",port_manager.node_count);
    pthread_exit(NULL);
}

//Wrapped Linklayer callback function
int wrappedLinkCallback(const void* __buffer, const void* __mac_addr, int len, int index, uint16_t proto){
    return LinkCallback(__buffer,__mac_addr,len, index, proto);
}

//Wrapped IPlayer callback function
int wrappedIPCallback(const void* __buffer, const IPHeader header, int len, int index){
    return IPCallback(__buffer, header, len, index);
}


void* moniter(void* vargs){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *it;


    printf("child process, current pid = %08x\n", (uint32_t)pthread_self());

    int result;
    result = pcap_findalldevs(&alldevs, errbuf);  
    uint8_t mac_addr[8];
    struct in_addr ip_addr;
    for (it = alldevs; it != NULL; it = it->next){
        bool tag = true;
        if (findMac(it->name, mac_addr) == -1) tag = false;
        if (findIP(it->name, ip_addr) == -1) tag = false;
        if (tag == true)
            addDevice(it->name);
    }

    port_manager.set_device();

    for (int i = 0; i < d_manager.count(); i++){
        setFrameReceiveCallback(wrappedLinkCallback, i);
        setIPPacketReceiveCallback(wrappedIPCallback, i);
    }
    fin_initialize = true;

    long long receivetic = gettime() + RECEIVE_GAP;
    long long retranstic = gettime() + RETRANS_GAP;
    int tims = 0;
    for (;;){
        if (fin_sigint) break;
        if (gettime() > receivetic){
            int sem_v;
            sem_getvalue(&sem, &sem_v);
            sem_wait(&sem);
            for (int i = 0; i < d_manager.count(); i++) receiveAllFrame(i, 10);
            receivetic = gettime() + RECEIVE_GAP;
            sem_post(&sem);
        }
        if (gettime() > retranstic){
            int sem_v;
            sem_getvalue(&sem, &sem_v);
            sem_wait(&sem);
            for (int i = 0; i < socket_manager.node_count; i++)
                if (socket_manager.mem[i] != NULL){
                    struct SocketNode* nd = socket_manager.mem[i];
                    nd->retransmit();
                }
            retranstic = gettime() + RETRANS_GAP;
            sem_post(&sem);
        }
    }

    printf("child process fin\n");
    child_proc = false;
    pthread_exit(NULL);
    return NULL;
    
    //exit(0);
}

void init_kern(){
    static bool initialized = false;
    if (initialized) return;
    
    initialized = true;
    sem_init(&sem, 0, 1);
    //signal(SIGINT, SIGINT_handler);
    pthread_create(&tid, NULL, moniter, NULL);

    fprintf(stderr, "parent thread, current pid = %08x\n", (uint32_t)pthread_self());
    
    while (!fin_initialize);
    return;
}

#endif
