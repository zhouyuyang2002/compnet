/* *
* @file constant.h
* @brief define the constants used in the lab
*/

#ifndef MYCONSTANT_H
#define MYCONSTANT_H

#include <netinet/ether.h>
#include <arpa/inet.h>
#include "type.h"

const uint32_t sizethhdr = sizeof(struct ethhdr);
const int32_t BYTE_IN_ROW = 0x10;
const uint32_t COMPILEBUF_SIZE = 0x100;

#define ETHERNET 0x01
#define IPPROTOCOL 0x0800
#define ARPPROTOCOL 0x0806
#define DTRPPROTOCOL 0x0806
#define TCPPROTOCOL 0x06

#define NO_FRAG 0x20
#define MAY_FRAG 0x00
#define MORE_FRAG 0x10
#define LAST_FRAG 0x00

const size_t PACKETLEN = 0x800;    
const size_t WNDVAL = 0x8000;     


const struct macAddress __broadcast_addr = {{0xff,0xff,0xff,0xff,0xff,0xff}};
const struct in_addr __full_mask = {0xffffffff};
const struct in_addr __no_mask = {0xffffffff};

#endif