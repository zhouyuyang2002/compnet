/* *
* @file constant.h
* @brief define the constants used in the lab
*/

#ifndef MYCONSTANT_H
#define MYCONSTANT_H

#include <netinet/ether.h>
#include <arpa/inet.h>
const uint32_t sizethhdr = sizeof(struct ethhdr);
const int32_t BYTE_IN_ROW = 0x10;
const uint32_t COMPILEBUF_SIZE = 0x100;

#endif