#ifndef MYSOCKET_H
#define MYSOCKET_H
#include "device.h"
#include "ip.h"
#include "arp.h"
#include "portal.h"
#include "moniter.h"
#include "portmanager.h"
#include <semaphore.h>

# include <sys/types.h>
# include <sys/socket.h>
# include <netdb.h>

int __wrap_socket(int domain ,int type ,int protocol){
    init_kern();
    sem_wait(&sem);
    int result = socket_manager.append(domain, type, protocol);
    sem_post(&sem);
    return result;
}
int __wrap_bind(int socket, const struct sockaddr* address, socklen_t address_len){
    init_kern();
    if (socket_manager.find(socket) < 0)
        errhandle("socket index not found!");
    struct sockaddr_in addr = *((struct sockaddr_in*) address);
    addr.sin_addr.s_addr = htonl(addr.sin_addr.s_addr);
    addr.sin_port = htons(addr.sin_port);
    int result = port_manager.find(addr);

    if (result == -E_NO_IP)
        errhandle("no such IP address!");
    if (result == 0)
        errhandle("port already exists!");

    sem_wait(&sem);
    socket_manager[socket]->bind(address);
    sem_post(&sem);
    return 0;
}
int __wrap_listen(int socket, int backlog){
    init_kern();
    if (socket_manager.find(socket) < 0)
        errhandle("socket index not found!");
    sem_wait(&sem);
    int result = socket_manager[socket]->listen(backlog);
    sem_post(&sem);
    return result;
}
int __wrap_connect(int socket, const struct sockaddr * address, socklen_t address_len){
    init_kern();
    if (socket_manager.find(socket) < 0)
        errhandle("socket index not found!");
    struct sockaddr_in addr = *((struct sockaddr_in*) address);
    addr.sin_addr.s_addr = htonl(addr.sin_addr.s_addr);
    addr.sin_port = htons(addr.sin_port);
    struct in_addr ipaddr;
    ipaddr.s_addr = addr.sin_addr.s_addr;
    char __nextHopMac[10];
    int __index;
    if (getNextHopMac(ipaddr, __nextHopMac, __index))
        errhandle("no such address!");
    sem_wait(&sem);
    int result = socket_manager[socket]->connect(address);
    sem_post(&sem);
    return result;
}
int __wrap_accept(int socket, const struct sockaddr * address, socklen_t* address_len){
    init_kern();
    if (socket_manager.find(socket) < 0)
        errhandle("socket index not found!");
    sem_wait(&sem);
    int result = socket_manager[socket]->accept(address);
    if (address_len != NULL)
        *address_len = sizeof(struct sockaddr_in);
    sem_post(&sem);
    return result;
}
ssize_t __wrap_read(int fildes, void * buf, size_t nbyte){
    init_kern();
    if (socket_manager.find(fildes) < 0){
        fprintf(stderr, "warning: socket not found!");
        return read(fildes, buf, nbyte);
    }
    sem_wait(&sem);
    int result = socket_manager[fildes]->read(buf, nbyte);
    sem_post(&sem);
    return result;
}
ssize_t __wrap_write(int fildes, const void* buf, size_t nbyte){
    init_kern();
    if (socket_manager.find(fildes) < 0){
        fprintf(stderr, "warning: socket not found!");
        return write(fildes, buf, nbyte);
    }
    sem_wait(&sem);
    int result = socket_manager[fildes]->write(buf, nbyte);
    sem_post(&sem);
    return result;
}
int __wrap_close(int fildes){
    init_kern();
    if (socket_manager.find(fildes) < 0)
        return close(fildes);
    sem_wait(&sem);
    socket_manager.remove(fildes);
    sem_post(&sem);
    return 0;
}
int __wrap_getaddrinfo(const char* node, const char* service, const struct addrinfo *hints, struct addrinfo** res){
    init_kern();
    if (node == NULL){
        if (service == NULL)
            errhandle("bad request: Both node and service are NULL");
        struct addrinfo* ans = new struct addrinfo;
        ans -> ai_flags = 0;
        ans -> ai_family = AF_INET;
        ans -> ai_socktype = SOCK_STREAM;
        ans -> ai_protocol = IPPROTO_TCP;
        ans -> ai_addrlen = sizeof(struct sockaddr_in);
        struct sockaddr_in* addr = new sockaddr_in;
        addr -> sin_family = htons(AF_INET);
        addr -> sin_port = htons(atoi(service));
        addr -> sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ans -> ai_addr = (struct sockaddr*) addr;
        ans -> ai_canonname = NULL;
        ans -> ai_next = NULL;
        *res = ans;
        return 0;
    }
    in_addr_t __ip_addr = ntohl(inet_addr(node));
    printf("hex ip_addr = %08x\n", __ip_addr);
    struct in_addr ip_addr = *((in_addr*)&__ip_addr);
    uint16_t port = (service == NULL ? 0 : (uint16_t)atoi(service));

    char Hop[10];
    int index;

    if (getNextHopMac(ip_addr, Hop, index))
        errhandle("Bad request: Device not found!");
    struct addrinfo ans;
    ans.ai_flags = 0;
    ans.ai_family = htonl(AF_INET);
    ans.ai_socktype = htonl(SOCK_STREAM);
    ans.ai_protocol = htonl(IPPROTO_TCP);
    ans.ai_addrlen = sizeof(struct sockaddr_in);
    struct sockaddr_in* addr = new struct sockaddr_in;
    addr -> sin_family = htons(AF_INET);
    addr -> sin_port = htons(port);
    addr -> sin_addr = ip_addr;
    ans.ai_addr = (struct sockaddr*) addr;
    ans.ai_canonname = NULL;
    ans.ai_next = NULL;
    *res = &ans;
    return 0;
}

void __wrap_freeaddrinfo(const struct addrinfo *itr){
    for (;itr != NULL;){
        struct addrinfo* ptr = itr -> ai_next;
        delete itr -> ai_addr;
        delete itr;
        itr = ptr;
    }
}

#endif