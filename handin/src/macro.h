/* *
* @file macro.h
* @brief define the macros used in the lab
*/

#ifndef MYMACRO_H
#define MYMACRO_H

#define errhandle(...) do{\
    fprintf(stderr,__VA_ARGS__);\
    return -1;\
} while(0)

#define printmac(mac_addr); printf(\
    "%02x:%02x:%02x:%02x:%02x:%02x",\
    (unsigned char)mac_addr[0],(unsigned char)mac_addr[1],(unsigned char)mac_addr[2],\
    (unsigned char)mac_addr[3],(unsigned char)mac_addr[4],(unsigned char)mac_addr[5]);

#define printip(ip_addr) do {\
    struct in_addr temp;\
    temp.s_addr = htonl(ip_addr.s_addr);\
    printf("%s",inet_ntoa(temp));} while(0)

/*
* Swap two items
*/
template<class T> void swap(T &a,T &b){
    T temp = a; a = b; b = temp;
}
#endif