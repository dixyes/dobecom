/*
utils.c - dobecom some func header
by dixyes (dixyes@gmail.com)

*/
#include <stdint.h>

#ifndef _DOGE_UTILS
#define _DOGE_UTILS

extern void error(const char *msg);
extern uint32_t chksum(void *input,int len);
#ifdef _DEBUG
extern uint64_t rand_interval(uint64_t min, uint64_t max);
extern void printx(void*buf,uint16_t len);
extern char * sprintx(void*buf,uint16_t len);
#endif // _DEBUG
#ifdef _WIN32
extern void sleep(unsigned int seconds);
#endif // _WIN32
#endif // _DOGE_UTILS
