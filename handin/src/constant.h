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

#define NO_FRAG 0x2
#define MAY_FRAG 0x0
#define MORE_FRAG 0x1
#define LAST_FRAG 0x0


const struct macAddress __broadcast_addr = {{0xff,0xff,0xff,0xff,0xff,0xff}};
const struct in_addr __full_mask = {0xffffffff};
const struct in_addr __no_mask = {0xffffffff};

#endif