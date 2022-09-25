/* *
* @file macro.h
* @brief define the macros used in the lab
*/

#ifndef MYMACRO_H
#define MYMACRO_H

#define errhandle(...) {\
    fprintf(stderr,__VA_ARGS__);\
    return -1;\
}

#define printmac(mac_addr); printf(\
    "%02x:%02x:%02x:%02x:%02x:%02x",\
    (unsigned char)mac_addr[0],(unsigned char)mac_addr[1],(unsigned char)mac_addr[2],\
    (unsigned char)mac_addr[3],(unsigned char)mac_addr[4],(unsigned char)mac_addr[5]);

#endif