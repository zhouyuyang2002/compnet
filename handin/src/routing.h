/* *
* @file routing.h
* @brief Library for a data structure which found the mac address
* of the next Hop accroding to some hopping rules.
*/

#ifndef ROUTING_H
#define ROUTING_H

#include "type.h"
#include "constant.h"
#include "macro.h"
#include <string.h>
#include <stdlib.h>

struct RoutingTableNode{
    bool rule;                         // if the node contains a routing rule
    std::pair<macAddress, int> value;  // the routing rule in (next hop address, next hop device index) format
    int child[2];                      // the child node

    RoutingTableNode(){
        rule = false;
        child[0] = child[1] = -1;
    }
};

struct RoutingTable{
    RoutingTableNode* mem; // the pointer to the memory, which save the nodes in the trie
    int node_released;     // the number of nodes in the trie 
	int node_count;        // the maximum number of nodes mem can save. 

    RoutingTable(){
        mem = new RoutingTableNode[1];
        node_released = node_count = 1;
    }
    ~RoutingTable(){
        delete[] mem;
    }

    int newNode(){
        if (node_released == node_count){
            RoutingTableNode* newmem = new RoutingTableNode[2 * node_count + 1];
            memcpy(newmem, mem, sizeof(RoutingTableNode) * node_count);
            delete[] mem;
            mem = newmem;
            node_count = node_count * 2 + 1;
        }
        return node_released ++;
    }

	/* *
	* @brief set the given routing rule
	
	* @param dst the destination 
	* @param mask the mask of the destination
	* @param value the (next hop address, next hop device) pair
	*/
    void setNextHopMac(uint32_t dst, struct in_addr mask, std::pair<macAddress,int> value){
        int index = 0;
        for (int i = 31; i >= 0; i--){
            if (!(mask.s_addr & (1u << i))) break;
            uint32_t c = (dst >> i) & 1;
            if (mem[index].child[c] == -1){
                int nindex = newNode();
                mem[index].child[c] = nindex;
            }
            index = mem[index].child[c];
        }
        mem[index].rule = true;
        mem[index].value = value;
    }

	/* *
	* @brief find the (next hop address, next hop device) pair according to the rule set above
	* @param dst the destination v
	* @param value the pointer of (next hop address, next hop device) pair
	* @return 0 on at least one matching rules, -1 on no matching tules.
	*/
    int queryNextHopMac(uint32_t dst, std::pair<macAddress,int> *value){
        int index = 0, result = -1;
        if (mem[index].rule == true)
            result = index;
        for (int i = 31; i >= 0; i--){
            uint32_t c = (dst >> i) & 1;
            if (mem[index].child[c] == -1) break;
            index = mem[index].child[c];
            if (mem[index].rule == true)
                result = index;
        }
        if (result == -1)
            return -1;
        *value = mem[result].value;
        return 0;
    }
};

RoutingTable routing;

#endif