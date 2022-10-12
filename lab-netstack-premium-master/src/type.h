/* *
* @file types.h
* @brief define the constants used in the lab
*/

#ifndef MYTYPE_H
#define MYTYPE_H
#include <stdint.h>

typedef int (*frameReceiveCallback)(const void*, const void*, int, int, uint16_t);

/* *
* @brief Process an IP packet upon receiving it .
*
* @param buf Pointer to the packet .
* @param len Length of the packet .
* @return 0 on success , -1 on error .
* @see addDevice
*/
typedef int (*IPPacketReceiveCallback)(const void *, const struct IPHeader, int, int) ;

struct macAddress{
    uint8_t m_addr[6];
    uint8_t& operator [](const int &index){
        return m_addr[index];
    }
};


struct ARPHeader{
    unsigned short h_type;
    unsigned short p_type;
    unsigned char  h_length;
    unsigned char  p_length;
    unsigned short op_type;
    unsigned short dist;
    macAddress src_macaddr;
    struct in_addr src_ipaddr;
    macAddress dst_macaddr;
    struct in_addr dst_ipaddr;
};

struct IPHeader{
    #ifndef LITTIE_ENDIAN
        unsigned char IHL : 4;
        unsigned char version : 4;
    #else
        unsigned char version : 4;
        unsigned char IHL : 4;
    #endif
    unsigned char TofService;
    unsigned short length; 
    unsigned short identification;
    unsigned short flags: 3;
    unsigned short Fragoffset : 13;
    unsigned char time2live;
    unsigned char protocol;
    unsigned short checksum;
    struct in_addr src_addr;
    struct in_addr dst_addr;
    unsigned int options: 24;
    unsigned int padding: 8;

    void CalcCheckSum(){
        unsigned short* head = &identification;
        head = head - 1;
        int rows = IHL;
        unsigned short temp = checksum = 0;
        for (int i = 0; i < 2 * rows; i++){
            unsigned short val = *(head + 2 * i);
            if (val > (unsigned short)0xffff - temp)
                temp = temp + 1;
            temp = temp + val;
        }
        checksum = ~temp;
    }

    int CheckValid(){
        unsigned short* head = &identification;
        head = head - 1;
        int rows = IHL;
        unsigned short temp = 0;
        for (int i = 0; i < 2 * rows; i++){
            unsigned short val = *(head + 2 * i);
            if (val > (unsigned short)0xffff - temp)
                temp = temp + 1;
            temp = temp + val;
        }
        if (~temp)
            return -1;
        return 0;
    }
//65535-(65535-x+65535) = x-65535
//65535-x+65535-(x-65535)
};

#endif