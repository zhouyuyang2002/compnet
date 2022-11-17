#ifndef RETRANS_H
#define RETRANS_H

#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <iostream>

#define RETRANSLEN (0x40)
struct retransQueue{
    int len[RETRANSLEN];
    int sum_len, p_remove_len;
    int head, tail;
    retransQueue(){
        memset(len, 0, sizeof(len));
        sum_len = p_remove_len = head = tail = 0;
    }

    int update(int tot_len){
        /*if (tot_len < p_remove_len){
            fprintf(stderr, "warning: retransmission queue errorA!\n");
            return 0;
        }
        tot_len -= p_remove_len;
        p_remove_len = 0;*/
        if (tot_len < sum_len){
            fprintf(stderr, "warning: retransmission queue errorB!\n");
            return 0;
        }
        int rmv_len = 0;
        head = (head + 1) & (RETRANSLEN - 1);
        if (head == tail){
            tail = (tail + 1) & (RETRANSLEN - 1);
            rmv_len = len[head];
        }
        len[head] = tot_len - sum_len;
        sum_len = sum_len - rmv_len + len[head];
        assert(sum_len == tot_len);
        for (;tail != head && !len[tail];)
            tail = (tail + 1) & (RETRANSLEN - 1);
        return rmv_len;
    }

    void remove(int rmv_len){
        if (rmv_len > sum_len){
            p_remove_len += rmv_len - sum_len;
            rmv_len = sum_len;
        }
        if (!rmv_len) return;
        //printf("remove %d\n", rmv_len);
        for (;;){
            int v = rmv_len;
            if (v > len[tail]) v = len[tail];
            len[tail] -= v;
            rmv_len -= v;
            sum_len -= v;
            if (!rmv_len) break;
            tail = (tail + 1) & (RETRANSLEN - 1);
        }
        for (;tail != head && !len[tail];)
            tail = (tail + 1) & (RETRANSLEN - 1);
    }
}retransQ;
#endif