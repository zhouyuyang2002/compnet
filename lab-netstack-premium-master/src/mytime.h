/* *
* @file mytime.h
* @brief Library for microsecond timer
*/

#ifndef MYTIME_H
#define MYTIME_H

#include <time.h>
#include <sys/time.h>

/* *
* get the current time in microsecond(us)
* @return the current time in microsecond(us)
*/
long long gettime(){
    struct timeval tic;
    gettimeofday(&tic, NULL);
    return (long long)((long long)(tic.tv_sec) * 1000 * 1000 + tic.tv_usec);
}

#endif