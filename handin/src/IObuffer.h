#ifndef IOBUFFER_H
#define IOBUFFER_H
#include "type.h"
#include <string.h>

const int IOBUFSIZE = (1 << 10);
const int MAXIOBUFSIZE = (1 << 21);
#define E_BUFEXCEED 0x1
#define E_OUTOFBUF 0x2
struct IOBuffer{
    char* buffer;
    int buf_len;
    int buf_head;
    int buf_tail;
    IOBuffer(){
        buffer = new char[IOBUFSIZE];
        buf_len = IOBUFSIZE;
        buf_head = buf_tail = 0;
    }

    ~IOBuffer(){
        //fprintf(stderr, "iobuffer.h, iobuf\n");
        if (buffer != NULL){
            delete[] buffer;
            buffer = NULL;
        }
        //fprintf(stderr, "iobuffer.h, iobuf\n");
    }

    size_t buf_size(){
        return (buf_tail + buf_len - buf_head) & (buf_len - 1);
    }

    void copy_tobuf(char* buf, int len){
        if (buf_head <= buf_tail || (buf_head > buf_tail && len <= buf_len - buf_head))
            memcpy(buf, buffer + buf_head, size_t(len));
        else{
            memcpy(buf, buffer + buf_head, size_t(buf_len - buf_head));
            memcpy(buf + (buf_len - buf_head), buffer, size_t(len - (buf_len - buf_head)));
        }
    }

    void copy_frombuf(char* buf, int len){
        if (buf_tail + len <= buf_len)
            memcpy(buffer + buf_tail, buf, size_t(len));
        else{
            memcpy(buffer + buf_tail, buf, size_t(buf_len - buf_tail));
            memcpy(buffer, buf + (buf_len - buf_tail), size_t(len - (buf_len - buf_tail)));
        }
    }

    int append(char* buf, size_t len){
        if (len > MAXIOBUFSIZE - 1 - buf_size())
            len = MAXIOBUFSIZE - 1 - buf_size();
        if (len == 0)
            return len;
        int n_size = len + buf_size();
        if (len + n_size > buf_len){
            int buf_siz = buf_size();
            int nbuf_len = buf_len;
            for (;nbuf_len < n_size; nbuf_len <<= 1);
            char* n_buffer = new char[nbuf_len];
            copy_tobuf(n_buffer, buf_siz);
            delete[] buffer;
            buf_len = nbuf_len;
            buffer = n_buffer;
            buf_tail = buf_siz;
            buf_head = 0;
        }

        copy_frombuf(buf, len);
        buf_tail = (buf_tail + len) & (buf_len - 1);
        return len;
    }
    int find(char* buf, size_t len){
        if (!len)
            return 0;
        if (buf_size() < len)
            len = buf_size();
        copy_tobuf(buf, len);
        return len;
    }
    int remove(size_t len){
        if (buf_size() < len)
            len = buf_size();
        buf_head = (buf_head + len) & (buf_len - 1);
        return 0;
    }
};

#endif