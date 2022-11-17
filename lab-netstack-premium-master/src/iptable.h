/* *
* @file iptable.h
* @brief Library for a data structure which gives the mapping between
*        IP address and the information about IP address
*/

#ifndef IPTABLE_H
#define IPTABLE_H

#include "type.h"
#include "constant.h"
#include "macro.h"
#include <string.h>
#include <stdlib.h>

template<class T> 
struct IPTableNode{
    T value;      // The value saved in the trie node
    int child[4]; // The index of the 4 childs of the node

    IPTableNode(){
        memset(child, -1, sizeof(child));
    }
};

/*
* @brief Map the IP address to the information about the IP address
* @Method Using a 16 layer 4-branch trie to maintain the structure
*/
template<class T>
struct IPTable{
    IPTableNode<T>* mem; // the pointer to the memory, which save the nodes in the trie
    int node_released;   // the number of nodes in the trie
	int node_count;      // the maximum number of nodes mem can save. 

    IPTable(){
        mem = new IPTableNode<T>[1];
        node_released = node_count = 1;
    }
    ~IPTable(){

        //fprintf(stderr, "iptable.h, iptab\n");
        if (mem != NULL){
            delete[] mem;
            mem = NULL;
        }
        //fprintf(stderr, "iptable.h, iptab\n");
    }

    int newNode(){
        if (node_released == node_count){
            IPTableNode<T>* newmem = new IPTableNode<T>[2 * node_count + 1];
            memcpy(newmem, mem, sizeof(IPTableNode<T>) * node_count);
            delete[] mem;
            mem = newmem;
            node_count = node_count * 2 + 1;
        }
        return node_released ++;
    }

	/* *
	* @brief find if the information about IP address
	
	* @param addr the IP address to be checked
	* @return 1 on information exist, 0 on not found
	*/
    int find(const uint32_t &addr){
        int index = 0;
        for (int i = 15; i >= 0; i--){
            uint32_t ch = (addr >> (2 * i)) & 3;
            if (mem[index].child[ch] == -1)
                return 0;
            index = mem[index].child[ch];
        }
        return 1;
    }

	/*
	* @brief find if the information about IP address, and 
	* set the piece of memory if the information is not found
	
	* @param addr the IP address to be checked
	* @return the information
	*/
    T& operator [](const uint32_t &addr){
        int index = 0;
        for (int i = 15; i >= 0; i--){
            uint32_t ch = (addr >> (2 * i)) & 3;
            if (mem[index].child[ch] == -1){
                int nindex = newNode();
                mem[index].child[ch] = nindex;
            }
            index = mem[index].child[ch];
        }
        return mem[index].value;
    }
};

IPTable<macAddress> info;
IPTable<short> distance;
IPTable<bool> broadcast;

#endif