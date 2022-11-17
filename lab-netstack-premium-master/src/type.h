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
    #ifdef LITTLE_ENDIAN
        unsigned char IHL : 4;
        unsigned char version : 4;
    #else
        unsigned char version : 4;
        unsigned char IHL : 4;
    #endif
    unsigned char TofService;
    unsigned short length; 
    unsigned short identification;
    #ifdef LITTLE_ENDIAN
        unsigned short Fragoffset : 13;
        unsigned short flags: 3;
    #else
        unsigned short flags: 3;
        unsigned short Fragoffset : 13;
    #endif
    unsigned char time2live;
    unsigned char protocol;
    unsigned short checksum;
    struct in_addr src_addr;
    struct in_addr dst_addr;
    unsigned int options;

    void CalcCheckSum(){
        unsigned short* head = &identification;
        head = head - 1;
        int rows = IHL;
        unsigned short temp = checksum = 0;
        for (int i = 0; i < 2 * rows; i++){
            unsigned short val = *(head + i);
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
            unsigned short val = *(head + i);
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

struct TCPPseudoHeader{
    struct in_addr src_addr;
    struct in_addr dst_addr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t length;
};
struct TCPHeader{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t syn_num;
    uint32_t ack_num;
    #ifdef LITTLE_ENDIAN
        unsigned char __useless: 4;
        unsigned char offset: 4;
    #else
        unsigned char offset: 4;
        unsigned short __useless: 4;
    #endif
    unsigned char control;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
    uint32_t options;

    void CalcCheckSum(struct TCPPseudoHeader pseudo_header){
        unsigned short* head = &src_port;
        int rows = offset;
        unsigned short temp = checksum = 0;
        for (int i = 0; i < 2 * rows; i++){
            unsigned short val = *(head + i);
            if (val > (unsigned short)0xffff - temp)
                temp = temp + 1;
            temp = temp + val;
        }
        head = (unsigned short*)&pseudo_header;
        for (int i = 0; i < 6; i++){
            unsigned short val = *(head + i);
            if (val > (unsigned short)0xffff - temp)
                temp = temp + 1;
            temp = temp + val;
        }
        checksum = ~temp;
        //printf("checksum = %04x\n", temp);
    }

    int CheckValid(struct TCPPseudoHeader pseudo_header){
        unsigned short* head = &src_port;
        int rows = offset;
        unsigned short temp = 0;
        for (int i = 0; i < 2 * rows; i++){
            unsigned short val = *(head + i);
            if (val > (unsigned short)0xffff - temp)
                temp = temp + 1;
            temp = temp + val;
        }
        head = (unsigned short*)&pseudo_header;
        for (int i = 0; i < 6; i++){
            unsigned short val = *(head + i);
            if (val > (unsigned short)0xffff - temp)
                temp = temp + 1;
            temp = temp + val;
        }
        //printf("checksum = %04x\n", temp);
        if (temp != 0 && (temp != (unsigned short)0xffff))
            return -1;
        return 0;
    }
};

#endif