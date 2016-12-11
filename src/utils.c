/*
utils.c - dobecom some func
by dixyes (dixyes@gmail.com)

*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>


#include "utils.h"


#ifdef _WIN32
#include <time.h>
void sleep(unsigned int seconds)
{
    clock_t goal = seconds*1000 + clock();
    while (goal > clock());
}
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif // _WIN32
#ifdef _DEBUG
#include <string.h>
void printx(void*buf,uint16_t len)
{
    uint8_t* bufptr=buf;
    char pbuf[1024],pbuf1[1024];//=malloc(len*4*sizeof(uint8_t)),*pptr=pbuf;
    uint16_t ii;
    pbuf[0]=0;
    pbuf1[0]=0;
    for(ii=0; ii<len; ii++)
    {
        sprintf(pbuf,"%02x ",*(bufptr+ii));
        strcat(pbuf1,pbuf);
        if(!((ii+1)%8))
        {
            sprintf(pbuf,"  ");
            strcat(pbuf1,pbuf);
        }
        if((ii+1!=len)&&!((ii+1)%16))
        {
            sprintf(pbuf,"\n");
            strcat(pbuf1,pbuf);
        }
    }
    if(((ii+1)%16))
    {
        sprintf(pbuf,"\n");
        strcat(pbuf1,pbuf);
    }
    fprintf(stderr,pbuf1);
    //free(pbuf);
    //free(pbuf1);
}
char * sprintx(void*buf,uint16_t len)
{
    uint8_t* bufptr=buf;
    char pbuf[1024];
    char *pbuf1=malloc(len*4*sizeof(uint8_t));
    uint16_t ii;
    pbuf[0]=0;
    *pbuf1=0;
    for(ii=0; ii<len; ii++)
    {
        sprintf(pbuf,"%02x ",*(bufptr+ii));
        strcat(pbuf1,pbuf);
        if(!((ii+1)%8))
        {
            sprintf(pbuf,"  ");
            strcat(pbuf1,pbuf);
        }
        if((ii+1!=len)&&!((ii+1)%16))
        {
            sprintf(pbuf,"\n");
            strcat(pbuf1,pbuf);
        }
    }
    if(((ii+1)%16))
    {
        sprintf(pbuf,"\n");
        strcat(pbuf1,pbuf);
    }
    //free(pbuf);
    //free(pbuf1);
    return pbuf1;
}

uint64_t rand_interval(uint64_t min, uint64_t max)
{
    uint64_t r;
    const uint64_t range = 1 + max - min;
    const uint64_t buckets = RAND_MAX / range;
    const uint64_t limit = buckets * range;

    do
    {
        r = rand();
    }
    while (r >= limit);

    return min + (r / buckets);
}
#endif // _DEBUG
void error(const char *msg)
{
    int errnum=errno;
    perror(msg);
    exit(errnum);
}
uint32_t chksum(void *input,int len)
{
    uint32_t cptr,ret=1234;
    int i;//htonl(1234);//
    //uint8_t *rptr;
    //printx(input,4);
    for(i=0;i*4<len-4;i++){
        cptr=*((uint32_t*)(input+(i*4)));
        //printx((uint32_t*)&input+i*4,4);
        //printf("%08x\n",ret);
        ret^=cptr;
    }
    cptr=0;
    memcpy(&cptr,input+(i*4),len-(i*4)-1);
    ret^=cptr;
    //printf("%08x\n",ret);
    ret*= 1968;
    return ret;
}
