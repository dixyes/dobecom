/*
dobepkt.h - dobecom packet builder header
by dixyes (dixyes@gmail.com)

*/
#include <stdint.h>
#include "dobecom.h"


#ifndef _DOBEPKT_STRUCT
#define _DOBEPKT_STRUCT

#define T_CHAPKT 0x0100
#define T_CHRPKT 0x02
#define T_LGIPKT 0x0301
#define T_SUCPKT 0x04
#define T_KALPKT 0xff00
#define T_LGOPKT 0x0701
#define T_MSCPKT 0x07
#define T_MSGPKT 0x4d
#define T_FALPKT 0x05

#define DOBEMISC_LENGTH 40
#define DOBELGISUC_LENGTH 45
#define DOBELGOSUC_LENGTH 25

#define MTS_ROK 0x1000
#define MTS_FILE 0x1001
#define MTS_2800 0x2800

struct dobechapkt
{
    uint8_t head;
    uint8_t try_times;
    uint16_t time;
    uint8_t fixed_ver;
    uint8_t zeros[15];
};
struct dobechrpkt
{
    uint8_t head;
    uint8_t try_times;
    uint8_t time[2];
    uint8_t salt[4];
    uint8_t cli_ip[4];
    uint8_t uknown1[2];
    uint8_t fixed1[16];
    uint8_t zeros[34];
};
struct fixedlgiextinfo
{
    uint8_t type;
    uint8_t len;
    uint8_t rand[4];
    uint8_t mac[8];
    uint8_t auto_lgo;
    uint8_t bcastmode;
    uint8_t tail[2];
};
struct dobelgipkt
{
    uint8_t head;
    uint8_t type[2];
    uint8_t usr_lth;
    uint8_t md5a[16];
    uint8_t username[36];
    uint8_t ctrlchkstatus;
    uint8_t adapternum;
    uint8_t md5x[6];
    uint8_t md5b[16];
    uint8_t ipcount;
    uint8_t localips[4][4];
    uint8_t md5c[8];
    uint8_t ipdobe;
    uint8_t zeros1[4];
    uint8_t hostname[32];
    uint8_t pri_dns[4];
    uint8_t dhcp[4];
    uint8_t sec_dns[4];
    uint8_t wins_ip[8];
    uint8_t os_length[4];
    uint8_t os_major[4];
    uint8_t os_minor[4];
    uint8_t os_build[4];
    uint8_t os_uknown[4];
    uint8_t dobever[32];
    uint8_t zeros3[32];
    uint8_t sstring[40];
    uint8_t zeros4[24];
    uint8_t auth_version[2];
    struct fixedlgiextinfo lgiextinfo;
};

struct rorlgiextinfo
{
    uint8_t type;
    uint8_t len;
    uint8_t ror;
};
struct dobesucpkt
{
    uint8_t head;
    uint8_t fixed1[4];
    uint8_t used_time[4];
    uint8_t used_flux[4];
    uint8_t used_balc[4];
    uint8_t fixed2[6];
    uint8_t auth[16];
    uint8_t tail[6];
};
struct dobekalpkt
{
    uint8_t head;
    uint8_t md5a[16];
    uint8_t zeros[3];
    uint8_t auth[16];
    uint16_t time;
};
struct dobelgopkt//incomplate
{
    uint8_t head;
    uint8_t type[2];
    uint8_t usr_lth;
    uint8_t md5a[16];
    uint8_t username[36];
    uint8_t fixed[2];
    uint8_t md5x[6];
    uint8_t auth[16];
};
struct dobemsgpkt//incomplate
{
    uint8_t head;
    uint8_t type;
    uint8_t massage[];
};
struct dobemscpkt
{
    uint8_t head;
    uint8_t initiative;
    uint16_t type;
    uint8_t zerob;
    uint8_t mctype;
    uint8_t uknown1[2];
    uint16_t uknown2;
    uint16_t time;
    uint8_t zeros[4];
    uint8_t mm[16];
    uint8_t content[];
};
#endif

#ifndef _DOBEPKT_FUNCS
#define _DOBEPKT_FUNCS

#ifndef htonll
#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif

extern void *challegepkt(void);
extern void *loginpkt(void);
extern void *logoutpkt(void);
extern void *miscpkt(void);
extern void *heartpkt(void);
#endif
