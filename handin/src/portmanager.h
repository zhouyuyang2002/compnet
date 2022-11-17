#ifndef PORTMANAGER_H
#define PORTMANAGER_H

#include "device.h"

#define PORT_NUM 0x10000
#define E_NO_IP 1
#define E_NO_PORT -2
struct PortManager{
    int** port_mem;
    int node_count;
    PortManager(){
        port_mem = NULL;
    }

    void set_device(){
        node_count = d_manager.count();
        port_mem = new int*[node_count];
        for (int i = 0; i < node_count; i++){
            port_mem[i] = new int[PORT_NUM];
            for (int j = 0; j < PORT_NUM; j++)
                port_mem[i][j] = -1;
        }
    }

    ~PortManager(){
        //fprintf(stderr, "portm.h, pm\n");
        if (port_mem != NULL){
            for (int i = 0; i < node_count; i++)
                delete[] port_mem[i];
            delete[] port_mem;
            port_mem = NULL;
        }
        //fprintf(stderr, "portm.h, pm\n");
    }

    int checkaddr(const struct sockaddr_in &addr){
        if (port_mem == NULL)
            return -1;
        for (int i = 0; i < node_count; i++)
            if (d_manager[i] -> isEqualIP(addr.sin_addr))
                return i;
        return -1;
    }
    int find(const struct sockaddr_in &addr){
        int index = checkaddr(addr);
        if (index == -1)
            return -E_NO_IP;
        int port = addr.sin_port;
        
        if (port_mem[index][port] == -1)
            return -E_NO_PORT;
        return 0;
    }
    int& operator [](const struct sockaddr_in &addr){
        int index = checkaddr(addr);
        return port_mem[index][addr.sin_port];
    }
    int empty_port(int index, int sockid, unsigned short* result){
        for (int i = 0; i < 65536; i++)
            if (port_mem[index][i] == -1){
                port_mem[index][i]= sockid;
                *result = i;
                return 0;
            }
        return -1;
    }
}port_manager;

#endif