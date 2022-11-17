#include "device.h"
#include "packetio.h"
#include "name2addr.h"
#include "callback.h"
#include "socket.h"
#include "ip.h"
#include <signal.h>
#include <vector>

#include <pcap/pcap.h>


struct in_addr IPAddr[10];
struct addrinfo* adinfo[10];

struct addrManage{
    int __useless__;

    ~addrManage(){
        for (int i = 0; i < 10; i++)
            if (adinfo[i] != NULL){
                __wrap_freeaddrinfo(adinfo[i]);
                adinfo[i] = NULL;
            }
    }
}__addrManage;

struct command{
    std::string name;
    std::string description;
    void (*ptr)();
};
std::vector<command> cmds;

in_addr name2inaddr(const char* name){
    in_addr_t result = ntohl(inet_addr(name));
    return *((struct in_addr*)&result);
}
void __server_socket(){
    int id;
    scanf("%d", &id);
    if (id < 0 || id >= 10)
        return printf("invalid index of addr_info, [0,10) expected\n"),void(0);
    if (adinfo[id] == NULL)
        return printf("no such addrinfo\n"),void(0);
    int index = __wrap_socket(adinfo[id]->ai_family, adinfo[id]->ai_socktype, adinfo[id]-> ai_protocol);
    if (index == -1)
        printf("socket() error!\n");
    else
        printf("socket id: %d\n",index);
}

void __server_bind(){
    char __ip_addr[50];
    int ip_port, index;

    scanf("%s%d%d", __ip_addr, &ip_port, &index);
    struct sockaddr_in addr;
    addr.sin_addr = name2inaddr(__ip_addr);
    addr.sin_port = ip_port;
    addr.sin_addr.s_addr = htonl(addr.sin_addr.s_addr);
    addr.sin_port = htons(addr.sin_port);
    int result = __wrap_bind(index, (struct sockaddr*)&addr, sizeof(addr));
    if (result == -1)
        printf("bind() error!\n");
    else
        printf("bind() success!\n");
}
void __server_listen(){
    int backlog, index;
    scanf("%d%d",&backlog, &index);
    int result = __wrap_listen(index, backlog);
    if (result == -1)
        printf("listen() error!\n");
    else
        printf("listen() success!\n");
}
void __server_connect(){
    char __ip_addr[50];
    int ip_port, index;

    scanf("%s%d%d", __ip_addr, &ip_port, &index);
    struct sockaddr_in addr;
    addr.sin_addr = name2inaddr(__ip_addr);
    addr.sin_port = ip_port;
    addr.sin_addr.s_addr = htonl(addr.sin_addr.s_addr);
    addr.sin_port = htons(addr.sin_port);
    int result = __wrap_connect(index, (struct sockaddr*)&addr, sizeof(addr));
    if (result == -1)
        printf("connect() error!\n");
    else
        printf("connect() success!\n");
}

void __server_accept(){
    int index;
    scanf("%d", &index);
    if (socket_manager.find(index) < 0){
        fprintf(stderr, "socket index not found!");
        return;
    }
    struct sockaddr_in addr;
    int result = __wrap_accept(index, (struct sockaddr*)&addr, NULL);
    if (result == -1)
        printf("accept() error!\n");
    else{
        printf("accept() success!\n");
        addr.sin_addr.s_addr = htonl(addr.sin_addr.s_addr);
        addr.sin_port = htons(addr.sin_port);
        printf("IP Address:"); printip(addr.sin_addr);
        printf(", Port:"); printf("%d\n", addr.sin_port);
    }
}

char buffer[MAXIOBUFSIZE];
void __server_read(){
    int index, len;

    scanf("%d%d", &len, &index);
    int result = __wrap_read(index, buffer, len);
    if (result == -1)
        printf("read() error!\n");
    else{
        printf("read() success!\n");
        buffer[result] = 0;
        printf("info: %s\n",buffer);
    }
}
void __server_write(){
    int index, len;

    scanf("%s%d", buffer, &index);
    len = strlen(buffer);
    int result = __wrap_write(index, buffer, len);
    if (result == -1)
        printf("write() error!\n");
    else{
        printf("write() success! : length = %d\n", result);
        if (result != len) 
            printf("unwritten buffer: %s\n", buffer + result);
    }   
}

void __server_close(){
    int index;
    scanf("%d",&index);
    int result = __wrap_close(index);
    if (result == -1)
        printf("close() error!\n");
    else
        printf("close() success!\n");
}

void __server_getaddrinfo(){
    char __ip_addr[50];
    scanf("%s",__ip_addr);
    int index = -1;
    for (int i = 0; i < 10; i++)
        if (adinfo[i] == NULL){
            index = i;
            break;
        }
    if (index == -1)
        return printf("no enough space to save addrinfo!"),void(0);
    int result = __wrap_getaddrinfo(__ip_addr, NULL, NULL,  &adinfo[index]);
    if (result == -1)
        return printf("getaddrinfo() error!\n"),void(0);
    else
        printf("getaddrinfo() success! addrinfo index = %d\n", index);
    struct addrinfo* ptr = adinfo[index];
    for (;ptr; ptr = ptr -> ai_next){
        struct sockaddr_in addr = *((struct sockaddr_in*)ptr -> ai_addr);
        printf("addrinfo ip = %08x, port = %d\n", addr.sin_addr.s_addr, addr.sin_port);
    }
}
void __server_freeaddrinfo(){
    int id;
    scanf("%d",&id);
    if (id < 0 || id >= 10)
        return printf("invalid index of addr_info, [0,10) expected\n"),void(0);
    if (adinfo[id] == NULL)
        return printf("no such addrinfo\n"),void(0);
    freeaddrinfo(adinfo[id]);
    adinfo[id] = NULL;
    printf("freeaddrinfo() success!");
}
void __server_printinfo(){
    int id;
    scanf("%d",&id);
    if (socket_manager.find(id) < 0){
        fprintf(stderr, "socket index not found!");
        return;
    }
    SocketNode* nd = socket_manager[id];
    #define pstate(state, num) case state:\
        printf("state = ");\
        puts(num);\
        break;
    switch (nd->state){
        pstate(S_CLOSED, "CLOSED");
        pstate(S_LISTEN, "LISTEN");
        pstate(S_SYNSENT, "SYNSENT");
        pstate(S_SYNRCVD, "SYNRCVD");
        pstate(S_ESTAB, "ESTABLISHED");
        pstate(S_FINWAIT1, "FINWAIT1");
        pstate(S_FINWAIT2, "FINWAIT2");
        pstate(S_CLOSEWAIT, "CLOSEWAIT");
        pstate(S_TIMEWAIT, "TIMEWAIT");
        pstate(S_LASTACK, "LASTACK");
        default:
            printf("Illegal state number!\n");
            break;
    }
    if (!nd->connected){
        printf("connection not set up\n");
        return;
    }
    else{
        printf("connection success!\n");
        printf("Src ip: %08x\n", nd->addr.sin_addr.s_addr);
        printf("Dest ip: %08x\n", nd->dst_addr.sin_addr.s_addr);
        printf("Src port: %d\n", nd->addr.sin_port);
        printf("Dest port: %d\n",nd->dst_addr.sin_port);
        printf("Syn Num = %u\n",nd->syn.nxt);
        printf("fwait_buf_size = %u\n",(unsigned int)nd->fwait.buf_size());
        printf("fsend_buf_size = %u\n",(unsigned int)nd->fsend.buf_size());
        printf("freceive_buf_size = %u\n",(unsigned int)nd->freceive.buf_size());
    }


   #undef pstate(state, num) 
}

void __server_help(){
    for (int i = 0; i < cmds.size(); i++)
        std::cout << cmds[i].name << "() args: " << cmds[i].description << std::endl;
    fflush(stdout);
}


int main(int argc, char** argv){

    IPAddr[1] = (struct in_addr){0x0a640101};
    IPAddr[2] = (struct in_addr){0x0a640201};
    IPAddr[3] = (struct in_addr){0x0a640301};
    IPAddr[4] = (struct in_addr){0x0a640302};
    cmds.push_back((command){"socket", "id_addrinfo ", __server_socket});
    cmds.push_back((command){"bind", "ip_addr - dest ip address, id_port - port index, id_socket", __server_bind});
    cmds.push_back((command){"listen", "backlog, id_socket", __server_listen});
    cmds.push_back((command){"connect", "ip_addr - dest ip address, port - dest port number, id_socket", __server_connect});
    cmds.push_back((command){"accept", "ip_addr - dest ip address, port - dest port number, id_socket", __server_accept});
    cmds.push_back((command){"read", "len - length of string, id_socket", __server_read});
    cmds.push_back((command){"write", "str - string to write, id_socket", __server_write});
    cmds.push_back((command){"close", "id_socket", __server_close});
    cmds.push_back((command){"getaddrinfo", "ip_addr - dest ip address", __server_getaddrinfo});
    cmds.push_back((command){"getfreeinfo", "ip_addrinfo ", __server_freeaddrinfo});
    cmds.push_back((command){"printinfo", "id_socket ", __server_printinfo});
    cmds.push_back((command){"help", "", __server_help});

    while (true){

        printf("Kernel >:");
        fflush(stdout);
        std::string str;
        std::cin >> str;
        int index = -1;
        for (int i = 0; i < cmds.size(); i++)
            if (cmds[i].name == str)
                index = i;
        if (index != -1)
            cmds[index].ptr();
        else{
            printf("no such commands\n you can use 'help' to get command discriptions!\n");
            fflush(stdout);
        }
    }
    return 0;
}