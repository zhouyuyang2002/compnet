#ifndef MONITER_H
#define MONITER_H
#include "tcp.h"
#include "IObuffer.h"
#include "portmanager.h"
#include "retrans.h"
#include <iostream>
#include <semaphore.h>

bool spin;
sem_t sem;
const long long TIMEOUT = 60000000; // 60S  
char __buffer[MAXIOBUFSIZE];
enum sock_mode_t{
    M_NONE,
    M_BINDED,
    M_CLIENT,
    M_SERVER,
    M_CONNECT
};

enum sock_state_t{
    S_CLOSED,
    S_LISTEN,
    S_SYNSENT,
    S_SYNRCVD,
    S_ESTAB,
    S_FINWAIT1,
    S_FINWAIT2,
    S_CLOSEWAIT,
    S_CLOSING,
    S_LASTACK,
    S_TIMEWAIT
};

struct SynInfo
{
    uint32_t unack;
    uint32_t nxt;
    uint32_t window;
    uint32_t uptr;
    uint32_t wl_syn;
    uint32_t wl_ack;
    uint32_t ini_syn;
    SynInfo():ini_syn(0),window(WNDVAL){}
};

struct AckInfo
{
    uint32_t nxt;
    uint32_t window;
    uint32_t uptr;
    uint32_t ini_ack;
    AckInfo():ini_ack(0),window(WNDVAL){}
};
#define TCPCTL_URG 0x20
#define TCPCTL_ACK 0x10
#define TCPCTL_PSH 0x08
#define TCPCTL_RST 0x04
#define TCPCTL_SYN 0x02
#define TCPCTL_FIN 0x01
#define VWND 0x8000

bool in_range(uint32_t __l, uint32_t __r,uint32_t __val){
    uint64_t l(__l),r(__r),val(__val);
    if (r < l) r += (1ull << 32);
    if (val < l) val += (1ull << 32);
    return l <= val && val <= r;
}
struct SocketNode{
    int domain;
    int type;
    int protocol;
    int index;
    bool binded;
    bool passive;
    bool connected;
    sock_state_t state;
    struct sockaddr_in addr;
    struct sockaddr_in dst_addr;

    struct TCPHeader* trap_tcp_frame;
    struct IPHeader* trap_ip_frame;
    int trap_bound;
    int trap_count;

    SynInfo syn;
    AckInfo ack;
    IOBuffer freceive;
    IOBuffer fwait;
    IOBuffer fsend;
    IOBuffer festab;
    int finack;
    int timeout;

    retransQueue retransQ;

    bool closed;
    int hang;
    SocketNode(int __domain, int __type, int __protocol, int __index):
        domain(__domain),type(__type),protocol(__protocol),index(__index),
        state(S_CLOSED),binded(false),passive(false),trap_tcp_frame(NULL),
        trap_ip_frame(NULL){

        }

    ~SocketNode(){
    }


    void deal_estab(){
        char* buf = new char[PACKETLEN + 5];
        for (;fwait.buf_size() && (fsend.buf_size() != MAXIOBUFSIZE - 1);){
            //printf("len remaining %d\n", fwait.buf_size());
            size_t len = fwait.buf_size();
            if (len > PACKETLEN) len = PACKETLEN;
            if (len > MAXIOBUFSIZE - 1 - fsend.buf_size())
                len = MAXIOBUFSIZE - 1 - fsend.buf_size();
            fwait.find(buf, len);
            fwait.remove(len);
            buf[len] = 0;
            struct TCPHeader header;
            memset(&header, 0, sizeof(header));
            header.ack_num = ack.nxt;
            header.syn_num = syn.nxt;
            syn.nxt = syn.nxt + len;
            header.control = TCPCTL_ACK;
            /*ack.window = ack.window - len;*/
            sendTCPPacket(header, addr, dst_addr, buf, len);
            fsend.append(buf, len);
        }
        if (fwait.buf_size())
            fprintf(stderr, "warning : no sufficient buffer for waiting list\n");
    }
    int __close(){
        if (state == S_CLOSED)
            return 0;
        if (state == S_LISTEN || state == S_SYNSENT){
            closed = true;
            for (;hang >= 0;);
            state = S_CLOSED;
            return 0;
        }
        if (state == S_SYNRCVD){
            closed = true;
            for (;(state == S_SYNRCVD) || (state == S_ESTAB && hang););
            struct TCPHeader header;
            memset(&header, 0, sizeof(header));
            header.syn_num = syn.nxt;
            header.ack_num = ack.nxt;
            header.offset = 6;
            header.control = TCPCTL_ACK | TCPCTL_FIN;
            sendTCPPacket(header, addr, dst_addr, NULL, 0);
            state = S_FINWAIT1;
            return 0;
        }
        if (state == S_ESTAB){
            closed = true;
            for (;state == S_ESTAB && hang;);
            struct TCPHeader header;
            memset(&header, 0, sizeof(header));
            header.syn_num = syn.nxt;
            header.ack_num = ack.nxt;
            header.offset = 6;
            header.control = TCPCTL_ACK | TCPCTL_FIN;
            sendTCPPacket(header, addr, dst_addr, NULL, 0);
            state = S_FINWAIT1;
            return 0;
        }
        if (state == S_FINWAIT1 || state == S_FINWAIT2)
            errhandle("error : connection closed");

        if (state == S_CLOSEWAIT){
            sem_post(&sem);
            for (;hang;);
            sem_wait(&sem);
            struct TCPHeader header;
            memset(&header, 0, sizeof(header));
            header.syn_num = syn.nxt;
            header.ack_num = ack.nxt;
            header.offset = 6;
            header.control = TCPCTL_ACK | TCPCTL_FIN;
            sendTCPPacket(header, addr, dst_addr, NULL, 0);
            state = S_CLOSED;
            return 0;
        }
        errhandle("error : connection closed");
    }

    int close(){
        int result = __close();
        sem_post(&sem);
        for (;state != S_CLOSED;);
        sem_wait(&sem);
        return result;
    }

    int bind(const struct sockaddr *address){
        if (binded)
            errhandle("socket has alreadey been binded");
        struct sockaddr_in t_addr = *((struct sockaddr_in*) address);
        
        t_addr.sin_addr.s_addr = ntohl(t_addr.sin_addr.s_addr);
        t_addr.sin_port = ntohs(t_addr.sin_port);
        int result = port_manager.find(t_addr);
        if (result == -E_NO_IP)
            errhandle("invalud IP address");
        if (result != -E_NO_PORT)
            errhandle("port has already been used");
        binded = true;
        addr = t_addr;
        port_manager[t_addr] = index;
        return 0;
    }

    int listen(int backlog){
        if (!binded)
            errhandle("socket had not been binded\n");
        if (state == S_CLOSED){
            if (passive == true)
                errhandle("socket had already in LISTEN state\n");
            passive = true;
            state = S_LISTEN;
            trap_tcp_frame = new struct TCPHeader[backlog];
            trap_ip_frame = new struct IPHeader[backlog];
            trap_bound = backlog;
            trap_count = 0;
            return 0;
        }
        else
            errhandle("error: connection already exists\n");
    }
    int connect(const struct sockaddr *address){
        spin = true;
        if (binded)
            errhandle("socket had been binded\n");
        if (state == S_CLOSED){
            if (passive == true)
                errhandle("socket had already in passive connection\n");
            state = S_SYNSENT;


            struct sockaddr_in t_addr = *((struct sockaddr_in*)address);
            t_addr.sin_addr.s_addr = ntohl(t_addr.sin_addr.s_addr);
            t_addr.sin_port = ntohs(t_addr.sin_port);
            printf("%08x %d\n",t_addr.sin_addr.s_addr, t_addr.sin_port);
            char __nextHopMac[10];
            int __index;
            getNextHopMac(t_addr.sin_addr, __nextHopMac, __index);
            addr.sin_addr.s_addr = d_manager[__index] -> ip_addr.s_addr;
            if (port_manager.empty_port(__index, index, &addr.sin_port) == -1)
                errhandle("no free ports!");
            binded = true;

            //printf("%08x %d\n",addr.sin_addr.s_addr, addr.sin_port);
            dst_addr = t_addr;
            struct TCPHeader header;
            memset(&header, 0, sizeof(header));
            header.syn_num = htonl(syn.ini_syn);
            header.offset = 6;
            header.control = TCPCTL_SYN;
            syn.unack = syn.ini_syn;
            syn.nxt = syn.ini_syn + 1;
            header.window = syn.window = 1;
            //printf("%08x %d\n",t_addr.sin_addr.s_addr, t_addr.sin_port);
            sendTCPPacket(header, addr, dst_addr, NULL, 0);
            connected = false; spin = true;
            long long tic = gettime() + TIMEOUT;
            sem_post(&sem);
            for (;!connected && gettime() <= tic;);
            sem_wait(&sem);
            if (connected)
                return 0;
            errhandle("connection failed: timeout");
        }
        else if (state == S_LISTEN)
            errhandle("socket already in LISTEN state");
        else
            errhandle("connection alreasdy set up");
    }
    int accept(const struct sockaddr *__address){
        if (trap_ip_frame == NULL || trap_tcp_frame == NULL || state != S_LISTEN)
            errhandle("not in S_LISTEN state");
        if (trap_count == 0)
            errhandle("no existing connection requests");

        int index = 0;
        struct TCPHeader header;
        memset(&header, 0, sizeof(struct TCPHeader));
        ack.nxt = trap_tcp_frame[index].syn_num + 1;
        ack.ini_ack = trap_tcp_frame[index].syn_num;
        header.syn_num = syn.ini_syn;
        header.ack_num = ack.nxt;
        syn.nxt = syn.ini_syn + 1;
        syn.unack = syn.ini_syn;
        header.control = TCPCTL_SYN | TCPCTL_ACK;

        //puts("chk");
        struct sockaddr_in src_addr = addr;
        dst_addr.sin_addr = trap_ip_frame[index].src_addr;
        dst_addr.sin_port = trap_tcp_frame[index].src_port;
        if (__address != NULL){
            struct sockaddr_in t_addr = dst_addr;
            t_addr.sin_addr.s_addr = htonl(dst_addr.sin_addr.s_addr);
            t_addr.sin_port = htons(dst_addr.sin_port);
            *((struct sockaddr_in*)__address) = t_addr;
        }
        //puts("chk");
        sendTCPPacket(header, src_addr, dst_addr, NULL, 0);
        delete[] trap_tcp_frame;
        delete[] trap_ip_frame;
        trap_tcp_frame = NULL;
        trap_ip_frame = NULL;
        state = S_SYNRCVD;
        return 0;
        //todo list
    }
    int write(const void* buf, size_t len){
        if (state == S_CLOSED || state == S_LISTEN)
            errhandle("error: connection has not been set up");
        else if (state == S_SYNSENT || state == S_SYNRCVD){
            if (closed)
                errhandle("error : connection closed");
            ++hang;
            sem_post(&sem);
            long long tic = gettime() + TIMEOUT;
            for (;gettime() <= tic && (state == S_SYNSENT || state == S_SYNRCVD) && !closed;);
            sem_wait(&sem);
            if (closed){
                --hang;
                errhandle("error: connection closed");
            }
            --hang;
            int snd_len = fwait.append((char*) buf, len);
            if (snd_len != len)
                fprintf(stderr, "warning: insufficient resources in waiting buffer");
            return snd_len;
        }
        else if (state == S_ESTAB || state == S_FINWAIT1 || state == S_FINWAIT2){
            if (closed)
                errhandle("error: connection closed");
            int snd_len = fwait.append((char*) buf, len);
            if (snd_len != len)
                fprintf(stderr, "warning: insufficient resources in waiting buffer");
            deal_estab();
            return snd_len;
        }
        else
            errhandle("error: connection closed");
    }
    int read(void* buf, size_t len){
        if (state == S_CLOSED)
            errhandle("error : connection has not exist");
        else if (state == S_LISTEN || state == S_SYNSENT || state == S_SYNRCVD){
            if (closed)
                errhandle("error : connection closed");
            ++hang;
            sem_post(&sem);
            long long tic = gettime() + TIMEOUT;
            for (;(state == S_LISTEN || state == S_SYNSENT || state == S_SYNRCVD) && gettime() <= tic && !closed;);
            sem_wait(&sem);
            if (closed){
                --hang;
                errhandle("error : connection closed");
            }
            --hang;
            if (state != S_ESTAB)
                errhandle("error : connection time_out");
            if (len > freceive.buf_size())
                len = freceive.buf_size();
            freceive.copy_tobuf((char *)buf, len);
            freceive.remove(len);
            return len;
        }
        else if (state == S_ESTAB || state == S_FINWAIT1 || state == S_FINWAIT2){
            if (closed)
                errhandle("error : connection closed");
            if (len > freceive.buf_size())
                len = freceive.buf_size();
            freceive.copy_tobuf((char *)buf, len);
            freceive.remove(len);
            return len;
        }
        else if (state == S_CLOSEWAIT){
            if (closed)
                errhandle("error : connection closed");
            if (len < freceive.buf_size()){
                fprintf(stderr, "warning : no enough buffer to read");
                len = freceive.buf_size();
            }
            freceive.copy_tobuf((char *)buf, len);
            freceive.remove(len);
            return len;
        }
        else 
            errhandle("error : connection closed");
    }

    bool acceptable(struct SynInfo syn, struct AckInfo ack, struct TCPHeader header, int len){
        uint32_t seg_window = ack.window;
        if (seg_window == 0){
            if (len == 0)
                return ack.nxt == header.syn_num;
            else
                return false;
        }
        else{
            if (len == 0)
                return in_range(ack.nxt, ack.nxt + ack.window - 1, header.syn_num);
            else
                return in_range(ack.nxt, ack.nxt + ack.window - 1, header.syn_num) |
                       in_range(ack.nxt, ack.nxt + ack.window - 1, header.syn_num + len - 1);
        }
    }
    int packetHandle(struct IPHeader ip_header, struct TCPHeader tcp_header, char* buf, int len){
        //puts("suaihvlui");
        struct sockaddr_in src_addr,dst_addr;
        src_addr.sin_addr = ip_header.src_addr;
        dst_addr.sin_addr = ip_header.dst_addr;
        src_addr.sin_port = tcp_header.src_port;
        dst_addr.sin_port = tcp_header.dst_port;
        if (state == S_CLOSED){
            if (tcp_header.control & TCPCTL_RST)
                return 0; // ignore reset request
            
            struct TCPHeader header;
            memset(&header, 0, sizeof(header));
            if (tcp_header.control & TCPCTL_ACK){
                // reply ack request
                header.syn_num = tcp_header.ack_num;
                header.control = TCPCTL_RST;
            }
            else{
                // send ack request
                header.syn_num = 0;
                header.ack_num = tcp_header.syn_num + len;
                header.control = TCPCTL_RST | TCPCTL_ACK;
            }
            sendTCPPacket(header, dst_addr, src_addr, NULL, 0);
            return 0;
        }
        if (state == S_LISTEN){
            //printf("cfuck\n");
            if (tcp_header.control & TCPCTL_RST)
                return 0; //ignored
            struct TCPHeader header;
            memset(&header, 0, sizeof(header));
            if (tcp_header.control & TCPCTL_ACK){
                header.syn_num = tcp_header.ack_num;
                header.control = TCPCTL_RST;
                sendTCPPacket(header, dst_addr, src_addr, NULL, 0);
                return 0;
            }
            if (tcp_header.control & TCPCTL_SYN){
                printf("receive connection request from another device\n");
                printf("Ip : "); printip(src_addr.sin_addr); printf("Port :%d\n",src_addr.sin_port);
                int index = -1;
                for (int i = 0; i < trap_count; i++)
                    if (trap_tcp_frame[i].src_port == src_addr.sin_port)
                        if (trap_ip_frame[i].src_addr.s_addr == src_addr.sin_addr.s_addr)
                            index = i;
                if (index != -1){
                    trap_tcp_frame[index] = tcp_header;
                    trap_ip_frame[index] = ip_header;
                    return 0;
                }
                if (trap_count == trap_bound){
                    fprintf(stderr, "warning: no enough buffer to save clients");
                    return 0;
                }
                index = trap_count ++;

                trap_tcp_frame[index] = tcp_header;
                trap_ip_frame[index] = ip_header;
                return 0;
            }
            //drop the message;
            return 0;
        }
        if (state == S_SYNSENT){
            //printf("in jomake           ok\n");
            struct TCPHeader header;
            memset(&header, 0, sizeof(header));
            if (tcp_header.control & TCPCTL_ACK)
                if (!in_range(syn.ini_syn + 1, syn.nxt, tcp_header.ack_num)){
                    header.syn_num = tcp_header.ack_num;
                    header.control = TCPCTL_RST;
                    sendTCPPacket(header, dst_addr, src_addr, NULL, 0);
                    return 0;
                }
            if (tcp_header.control & TCPCTL_RST){
                if (in_range(syn.unack, syn.nxt, tcp_header.syn_num)){
                    printf("error: connection reset\n");
                    state = S_CLOSED;
                    connected = false;
                    return 0;
                }
                return 0;
            }
            //printf("in ok\n");
            /*
            */
            //ignore precedence & security check
            ack.nxt = tcp_header.syn_num + 1;
            ack.ini_ack = tcp_header.syn_num;
            if (in_range(syn.unack, tcp_header.syn_num, syn.unack + syn.window)){
                size_t remove_len = tcp_header.syn_num - syn.unack;
                syn.unack += remove_len;
                syn.window -= remove_len;
                retransQ.remove(remove_len);
                fsend.remove(remove_len);
            }
            if (in_range(syn.ini_syn, syn.ini_syn + (1u<<30), syn.unack)){
                fprintf(stderr, "connect success\n");
                header.syn_num = syn.nxt;
                header.ack_num = ack.nxt;
                header.control = TCPCTL_ACK;
                sendTCPPacket(header, dst_addr, src_addr, NULL, 0);
                connected = true;
                state = S_ESTAB;
                deal_estab();
                if (len != 0)
                    goto OTHER_STEP6;
                return 0;
            }
            else{
                header.syn_num = syn.ini_syn;
                header.ack_num = ack.nxt;
                header.control = TCPCTL_ACK | TCPCTL_SYN;
                state = S_SYNRCVD;
                sendTCPPacket(header, dst_addr, src_addr, NULL, 0);
                size_t size_used = festab.buf_size() + sizeof(len) + len + sizeof(struct TCPHeader) + sizeof(struct IPHeader);
                if (size_used >= MAXIOBUFSIZE)
                    errhandle("warning : no enough buffer for packet in state SYNSEND");
                festab.append((char*)&len, sizeof(len));
                festab.append((char*)&tcp_header, sizeof(struct TCPHeader));
                festab.append((char*)&ip_header, sizeof(struct IPHeader));
                festab.append((char* )buf, len);
                return 0;
            }
        }
        else{
            /*SYN-RECEIVED STATE, ESTABLISHED STATE, FIN-WAIT-1 STATE, FIN-WAIT-2 STATE
              CLOSE-WAIT STATE, CLOSING STATE, LAST-ACK STATE, TIME-WAIT STATE*/
            //printf("other step1\n");
            struct TCPHeader header;
            memset(&header, 0, sizeof(header));
            if (!acceptable(syn, ack, tcp_header, len)){
                if (!(tcp_header.control & TCPCTL_RST)){
                    header.syn_num = syn.nxt;
                    header.ack_num = ack.nxt;
                    header.control = TCPCTL_ACK;
                    sendTCPPacket(header, dst_addr, src_addr, NULL, 0);
                }
                return 0;
                //drop the packet
            }


            //printf("other step2\n");
            //Assume that packet are sent in seq_num order, and begins at ack.nxt
            //if not at ack.nxt, drop it(wait for resend)
            if (!in_range(ack.nxt, ack.nxt + MAXIOBUFSIZE, tcp_header.syn_num)){
                uint32_t dif = ack.nxt - tcp_header.syn_num;
                if (dif <= len){
                    buf += dif;
                    dif -= dif;
                    tcp_header.syn_num += dif;
                }
                else{
                    printf("warning: tcp_header.syn_num differ too much!\n");
                    return 0;
                }
                if (ack.window < len)
                    len = ack.window;
            }
            if (tcp_header.syn_num != ack.nxt){
                return 0;
                // wait for further retransmission
            }
            if (tcp_header.control & TCPCTL_RST){
                if (state == S_SYNRCVD){
                    if (passive == true)
                        state = S_LISTEN;
                    else{
                        state = S_CLOSED;
                        connected = passive = false;
                        fprintf(stderr, "connection refused");
                    }
                    retransQ.remove(fsend.buf_size());
                    fwait.remove(fwait.buf_size());
                    fsend.remove(fsend.buf_size());
                    festab.remove(festab.buf_size());
                    freceive.remove(freceive.buf_size());
                    return 0;
                }
                else if (state == S_ESTAB || state == S_FINWAIT1 || state == S_FINWAIT2 || state == S_CLOSEWAIT){
                    closed = true;
                    for (;hang;);
                    closed = false;
                    state = S_CLOSED;
                    connected = passive = false;
                    retransQ.remove(fsend.buf_size());
                    fwait.remove(fwait.buf_size());
                    fsend.remove(fsend.buf_size());
                    festab.remove(festab.buf_size());
                    freceive.remove(freceive.buf_size());
                    return 0;
                }
                else{
                    state = S_CLOSED;
                    connected = passive = false;
                    return 0;
                }
            }
            OTHER_STEP3:
            //ignore srcurity & precedence check
            OTHER_STEP4:
            //printf("other step4\n");
            if (tcp_header.control & TCPCTL_SYN){
                fprintf(stderr, "connection reset");
                closed = true;
                sem_post(&sem);
                for (;hang;);
                sem_wait(&sem);
                closed = false;
                state = S_CLOSED;
                connected = passive = false;
                retransQ.remove(fsend.buf_size());
                fwait.remove(fwait.buf_size());
                fsend.remove(fsend.buf_size());
                festab.remove(festab.buf_size());
                freceive.remove(freceive.buf_size());
                return 0;
            }

            OTHER_STEP5:
            //printf("other step5\n");
            if (!(tcp_header.control & TCPCTL_ACK))
                return 0;
            if (state == S_SYNRCVD){
                if (in_range(syn.unack, syn.nxt, tcp_header.ack_num)){
                    state = S_ESTAB;
                    connected = true;
                    deal_estab();
                    goto OTHER_STEP6;
                }
                else{
                    header.syn_num = tcp_header.ack_num;
                    header.control = TCPCTL_RST;
                    sendTCPPacket(header, dst_addr, src_addr, NULL, 0);
                    return 0;
                }
            }
            if (state == S_ESTAB || state == S_FINWAIT1 || state == S_FINWAIT2 || state == S_CLOSEWAIT || state == S_CLOSING){
                if (in_range(syn.unack + 1, syn.nxt, tcp_header.ack_num)){
                    size_t len = tcp_header.ack_num - syn.unack;
                    fsend.remove(len);
                    retransQ.remove(len);
                    syn.unack = tcp_header.ack_num;
                }
                else if (in_range(syn.nxt + 1, syn.nxt + MAXIOBUFSIZE, tcp_header.ack_num)){
                    header.syn_num = tcp_header.ack_num;
                    header.control = TCPCTL_ACK;
                    sendTCPPacket(header, dst_addr, src_addr, NULL, 0);
                    return 0;
                }
                else{
                    //return 0; ignored
                }
                //printf("baijinzhixing!\n");
                if (in_range(tcp_header.syn_num - MAXIOBUFSIZE, tcp_header.syn_num - 1, syn.wl_syn) ||
                    (in_range(tcp_header.ack_num - MAXIOBUFSIZE, tcp_header.ack_num - 1, syn.wl_ack) && tcp_header.syn_num == syn.wl_syn)){
                        syn.window = tcp_header.window;
                        syn.wl_syn = tcp_header.syn_num;
                        syn.wl_ack = tcp_header.ack_num;
                    }
                if (state == S_FINWAIT1){
                    if (in_range(syn.unack - MAXIOBUFSIZE, syn.unack - 1, finack))
                        state = S_FINWAIT2;
                }
                if (state == S_FINWAIT2){
                    if (!fsend.buf_size() && !fwait.buf_size()){

                    
                    //mention close();
                    //todo
                    }
                }
                if (state == S_CLOSING){
                    if (in_range(syn.unack - (1u << 30), syn.unack - 1, finack))
                        state = S_TIMEWAIT;
                }
                goto OTHER_STEP6;
            }
            if (state == S_LASTACK){
                if (in_range(syn.unack - (1u << 30), syn.unack - 1, finack)){
                    state = S_CLOSED;
                    connected = passive = false;
                    retransQ.remove(fsend.buf_size());
                    fwait.remove(fwait.buf_size());
                    fsend.remove(fsend.buf_size());
                    festab.remove(festab.buf_size());
                    freceive.remove(freceive.buf_size());
                }
                return 0;
            }
            if (state == S_TIMEWAIT){
                if (in_range(syn.unack - MAXIOBUFSIZE, syn.unack - 1, finack))
                    if (tcp_header.control & TCPCTL_FIN){
                        header.control = TCPCTL_ACK;
                        header.syn_num = tcp_header.ack_num;
                        sendTCPPacket(header, dst_addr, src_addr, NULL, 0);
                        timeout = 2 * TIMEOUT;
                    }
                return 0;
            }
            OTHER_STEP6:
            //printf("other step6\n");
            if (len == 0)                return 0;
            //ignore URG pointer
            if (state == S_ESTAB || state == S_FINWAIT1 || state == S_FINWAIT2){
                size_t rem = MAXIOBUFSIZE - freceive.buf_size();
                if (len > rem) len = rem;
                freceive.append(buf, len);
                ack.nxt = tcp_header.syn_num + len;
                header.syn_num = syn.nxt;
                header.ack_num = ack.nxt;
                header.control = TCPCTL_ACK;
                sendTCPPacket(header, dst_addr, src_addr, NULL, 0);
            }
            OTHER_STEP8:
            //printf("other step8\n");
            if (!(tcp_header.control & TCPCTL_FIN))
                return 0;
            if (state == S_LISTEN || state == S_CLOSED || state == S_SYNSENT)
                return 0;
            if (state == S_SYNRCVD || state == S_ESTAB){
                state = S_CLOSEWAIT;
                return 0;
            }
            if (state == S_FINWAIT1){
                if (in_range(syn.unack - MAXIOBUFSIZE, syn.unack - 1, finack)){
                    state = S_TIMEWAIT;
                    timeout = gettime() + 2 * TIMEOUT;
                }
                else
                    state = S_CLOSING;
                return 0;
            }
            if (state == S_FINWAIT2){
                state = S_TIMEWAIT;
                timeout = gettime() + 2 * TIMEOUT;
                return 0;
            }
            if (state == S_TIMEWAIT){
                timeout = 2 * TIMEOUT + gettime();
                return 0;
            }
            return 0;
        }
    }
    void retransmit(){
        int trans_len = retransQ.sum_len;
        int rmv_len = retransQ.update(fsend.buf_size());
        //printf("remove %d\n", rmv_len);
        fsend.remove(rmv_len);
        trans_len -= rmv_len;
        //printf("%d\n", trans_len);
        if (!trans_len) return;
        syn.nxt -= fsend.buf_size();
        fsend.copy_tobuf(__buffer, fsend.buf_size());
        __buffer[trans_len] = 0;
        for (int idx = 0; idx < trans_len;){
            int snd_len = trans_len - idx;
            if (snd_len > PACKETLEN) snd_len = PACKETLEN;
            struct TCPHeader header;
            memset(&header, 0, sizeof(header));
            header.ack_num = ack.nxt;
            header.syn_num = syn.nxt;
            syn.nxt = syn.nxt + snd_len;
            header.control = TCPCTL_ACK;
            sendTCPPacket(header, addr, dst_addr, __buffer + idx, snd_len);
            idx += snd_len;
        }
        syn.nxt -= trans_len;
        syn.nxt += fsend.buf_size();
    }
};

const int SOCKETSHIFT = 0x12345;

struct SocketManager{
    SocketNode** mem;
    int* free_mem;
    int node_count;
    SocketManager(){
        mem = NULL;
        free_mem = new int[1];
        free_mem[0] = node_count = 0;
    }
    ~SocketManager(){
        //fprintf(stderr, "portal.h, sm\n");
        if (mem != NULL){
            for (int i = 0; i < node_count; i++)
                if (mem[i] != NULL)
                    delete mem[i];
            delete[] mem;
            mem = NULL;
        }
        if (free_mem != NULL){
            delete[] free_mem;
            free_mem = NULL;
        }
        //fprintf(stderr, "portal.h, sm\n");
    }

    
    /* *
    * Return the pointer of the index-th DeviceNode
    * @param index The index of device to find
    */
    bool find(int index){
        index -= SOCKETSHIFT;
        if (index < 0 || index >= node_count || mem[index] == NULL)
            return false;
        return true;
    }
    SocketNode* operator [](int index){
        if (!find(index)){
            fprintf(stderr, "Invalid index in SocketManager");
            return NULL;
        }
        return mem[index - SOCKETSHIFT];
    }
    /* *
    * Add a device to the library for sending / receiving packets .
    *
    * @param device Name of network device to send / receive packet on .
    * @return A non - negative _device - ID_ on success , -1 on error .
    */

    int append(int domain ,int type ,int protocol){
        if (*free_mem == 0){
            SocketNode** n_mem = new SocketNode*[2 * node_count + 1];
            if (mem != NULL){
                memcpy(n_mem, mem, sizeof(SocketNode*) * node_count);
                delete[] mem;
            }
            mem = n_mem;
            delete[] free_mem;
            free_mem = new int[2 * node_count + 2];
            memset(free_mem, 0, sizeof(int) * (node_count * 2 + 2));
            for (int i = node_count; i <= 2 * node_count; i++)
                free_mem[++(*free_mem)] = i;
            node_count = 2 * node_count + 1;
        }
        int index = free_mem[(*free_mem)--];
        mem[index] = new SocketNode(domain, type, protocol, index + SOCKETSHIFT);
        return index + SOCKETSHIFT;
    }

    void remove(int fildes){
        int index = fildes - SOCKETSHIFT;
        mem[index] -> close();
        delete mem[index];
        mem[index] = NULL;
        free_mem[++(*free_mem)] = index;
    }
}socket_manager;

#endif