/*
main.c-dobecom main
by dixyes (dixyes@gmail.com)
progress socket and other things
*/
#ifdef _MSC_VER
#error "If you can make functions like getopt ,you can use VS"
#endif
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <Ws2tcpip.h>
#endif

#if defined(__linux__) || defined(__MACH__)
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#endif

#include "version.h"
#include "dobepkt.h"
#include "dobecom.h"
#include "utils.h"

time_t bftime;
int sock;
int16_t i;
#if defined(__linux__) || defined(__MACH__)
pthread_t thread[2];
#endif
#ifdef _WIN32
HANDLE handle;
#endif // _WIN32


struct dobeinfo info;
struct workstate state;
struct dobeoptions options;

int init_socket(struct dobeinfo *);
void usage(void);
unsigned int usend(int,uint16_t);
int urecv(int);
void sigproc (int);

void *udial(void *);
void *ukplv(void *);
#if defined(__linux__) || defined(__MACH__)
void *ulogout(void *);
void *ulisten(void *);
#endif // defined
#ifdef _WIN32
unsigned int __stdcall ulisten(void *);
unsigned int __stdcall ulogout(void *);
#endif // _WIN32

int main(int argc,char *argv[])
{
#ifdef _DEBUG
    for(int dei1=0; dei1<argc; dei1++)
        printf("%s ",argv[dei1]);
    printf("\n");
#endif // _DEBUG

    int opt=0;
    struct sockaddr_in tmpaddr;

    printf("Dobecom - redesigned dogecom for complex envir0nment build %d\n",BUILDS_COUNT);

    memset((char *)&info, 0, sizeof(info));
    memset((char *)&state, 0, sizeof(state));
    memset((char *)&options, 0, sizeof(options));

//defalut info
    info.ctrlchkstatus=D_CONTROLCHECKSTATUS;
    info.adapternum=D_ADAPTERNUM;
    memcpy(info.auth_version,D_AUTH_VERSION,2);
//arguscan:

    opterr = 0;
    while ((opt = getopt(argc, argv, "c:a:m:p:u:s:l:i:n:t:N:d:H:S:O:ABDHPTXfhv")) != -1)
    {
        switch (opt)
        {
        case 'm':
            info.mac=strtoll(optarg,NULL, 16);
            break;
        case 'u':
            strcpy(info.username,optarg);
            if(strlen(info.username)>MAX_USRNM)
            {
                fprintf(stderr,"Username is too long\n");
                exit(E2BIG);
            }
            break;
        case 'p':
            strcpy(info.password,optarg);
            if(strlen(info.password)>MAX_PWD)
            {
                fprintf(stderr,"Password is too long\n");
                exit(E2BIG);
            }
            break;
        case 's':
            if((state.serveraddr.sin_addr.s_addr=inet_addr(optarg))==0)
            {
                fprintf(stderr,"Wrong server IP\n");
                exit(EINVAL);
            }
            break;
        case 'i':
            if((state.localaddr.sin_addr.s_addr=inet_addr(optarg))==0)
            {
                fprintf(stderr,"Wrong local binding IP\n");
                exit(EINVAL);
            }
            break;
        case 'l':
            if(info.lcount<4)
            {
                if((tmpaddr.sin_addr.s_addr=inet_addr(optarg))==0)
                {
                    fprintf(stderr,"Wrong local dialing IP %s\n",optarg);
                    exit(EINVAL);
                }
                memcpy(info.localips[info.lcount++],&tmpaddr.sin_addr.s_addr,4);
            }
            else
                fprintf(stderr,"Extra local dialing IP %s ,ignore it.\n",optarg);
            break;
        case 'a':
            info.adapternum=atoi(optarg);
            break;
        case 'N':
            if((tmpaddr.sin_addr.s_addr=inet_addr(optarg))==0)
            {
                fprintf(stderr,"Wrong pri DNS IP %s\n",optarg);
            }
            memcpy(info.pdnsip,&tmpaddr.sin_addr.s_addr,4);
            break;
        case 'd':
            if((tmpaddr.sin_addr.s_addr=inet_addr(optarg))==0)
            {
                fprintf(stderr,"Wrong DHCP server IP %s\n",optarg);
            }
            memcpy(info.dhcpip,&tmpaddr.sin_addr.s_addr,4);
            break;
        case 'n':
            if((tmpaddr.sin_addr.s_addr=inet_addr(optarg))==0)
            {
                fprintf(stderr,"Wrong secondary DNS IP %s\n",optarg);
            }
            memcpy(info.sdnsip,&tmpaddr.sin_addr.s_addr,4);
            break;
        case 'H':
            strcpy(info.dobever,optarg);
            break;
        case 'S'://strange string
            strcpy(info.sstring,optarg);
            break;
        case 'O'://options
            if(strcmp(optarg,"fixedtrytimes")==0)
            {
                options.cha_fixed_trytimes=true;
            }
            if(strcmp(optarg,"winver")==0)
            {
                options.lgi_use_win_ver=true;
            }
            if(strcmp(optarg,"ror")==0)
            {
                options.ror=true;
            }
            break;
        case 'A':
            state.autologout=true;
            break;
        case 'B':
            state.broadcast=true;
            break;
        case 'D'://norm dhcp dial
        case 'C'://change pass
        case 'X'://8021x dial
        case 'P'://pppoe dial
        case 'L'://only login
        case 'h'://help
            state.mode=opt;
            break;
        case 'v':
            options.verbose = 5;
            break;
        }
    }
//todo:argu check
    if (opterr)
    {
        usage();
        exit(opterr);
    }
//default info setting:


    switch(state.mode)
    {
    case 'D':
    case 'L':
        sock=init_socket(&info);
        signal(SIGTERM,sigproc);
        signal(SIGINT,sigproc);
#if defined(__linux__) || defined (__MACH__)
        if(pthread_create(&thread[0], NULL, ulisten, NULL) != 0)
            error("pthread_create");
        while(true)
        {
        if(pthread_create(&thread[1], NULL, udial, NULL) != 0)
            error("pthread_create");
        if(thread[1] !=0)
        {
            pthread_join(thread[1],NULL);
            printf("[main] dial done\n");
        }
        if(state.mode=='L'&&state.loggedin)
        {
            ulogout(NULL);
            exit(0);
        }
        if(pthread_create(&thread[1], NULL, ukplv, NULL) != 0)
            error("pthread_create");
        if(thread[1] !=0)
        {
            pthread_join(thread[1],NULL);
            printf("[main] kplv timeout,redial\n");
        }
        }
#endif // __linux__
#ifdef _WIN32
        if(_beginthreadex(NULL, 2048, ulisten,NULL,0, NULL)==0)
            error("thread create");
        while(true)
        {
        udial(NULL);
        if(state.loggedin)
            printf("[main] dial done\n");
        if(ukplv(NULL)==NULL)
            printf("[main] kplv timeout,redial\n");
        }
#endif // _WIN32

    case 'h':
    case 'H':
        usage();
        break;
    }

    return 0;
}

void sigproc (int cause)
{
    if(cause==SIGTERM)
        exit(SIGTERM);
    if(cause==SIGINT)
        fprintf(stderr,"[sigproc] keyboard int\n");
    if(state.loggedin)
    {
#if defined(__linux__) || defined(__MACH__)
        if(pthread_create(&thread[1], NULL, ulogout, NULL) != 0)
            error("pthread_create");
#endif
#ifdef _WIN32
        if(_beginthreadex(NULL,2048, ulogout,NULL,0, NULL) == 0)
            error("pthread_create");
#endif // _WIN32
    }


#ifdef _WIN32
        WSACleanup();
#endif // _WIN32
    bftime=time(NULL);
    while((bftime>time(NULL)-WAIT_TIME)&&(state.loggedin));
    state.exiting=true;
    close(sock);
    exit(cause);
}

int init_socket(struct dobeinfo *info)
{
    //struct timeval tv;

#ifdef _WIN32
    WSADATA wsaData;
    if(WSAStartup(MAKEWORD(2, 2), &wsaData))
        error("WSAStartup");
#endif
    if ((sock=socket(AF_INET, SOCK_DGRAM,0)) < 0)
        error("socket");
    state.localaddr.sin_family=AF_INET;
    state.serveraddr.sin_family=AF_INET;
    state.localaddr.sin_port=htons(DOBE_CLI_PORT);
    state.serveraddr.sin_port=htons(DOBE_SVR_PORT);
    if(state.localaddr.sin_addr.s_addr==0)
        state.localaddr.sin_addr.s_addr=htonl(INADDR_ANY);
    if(state.serveraddr.sin_addr.s_addr==0)
        state.serveraddr.sin_addr.s_addr=inet_addr(D_SVR_IP);
    if(bind(sock,(struct sockaddr *)&(state.localaddr),sizeof(struct sockaddr_in))<0)
        error("binding");

    return sock;
}
#if defined(__linux__) || defined(__MACH__)
void *ulogout(void * ptr)
#endif // defined
#ifdef _WIN32
unsigned int __stdcall ulogout(PVOID pM)
#endif // _WIN32
{
    while((!state.salt_got)&&(state.challegecount<MAX_CHA_TRY))
    {
        i=usend(sock,T_CHAPKT);
        bftime=time(NULL);
        if(options.verbose>4)
            printf("[ulogout] %d bytes sent\n",i);
        while((bftime>time(NULL)-WAIT_TIME)&&(!state.salt_got));
        if(state.salt_got)
            break;
    }
    if(state.challegecount>=MAX_CHA_TRY)
    {
        fprintf(stderr,"[ulogout] cha fail\n");
        exit(-1);
    }
    if(state.salt_got)
    {
        i=usend(sock,T_LGOPKT);
    if(options.verbose>3)
        printf("[ulogout] logout sent\n");
    }
#if defined(__linux__) || defined(__MACH__)
    pthread_exit(NULL);
    return NULL;
#endif
#ifdef _WIN32
    return 0;
#endif // _WIN32
}
#if defined(__linux__) || defined(__MACH__)
void *ulisten(void * ptr)
#endif // defined
#ifdef _WIN32
unsigned int __stdcall ulisten(PVOID pM)
#endif // _WIN32
{
    while(!state.exiting)
        if((i=urecv(sock))>0)
        {
            if(options.verbose>4)
                    printf("[ulisten] %d bytes recv\n",i);
        }
        else
            fprintf(stderr,"[ulisten] error receiving\n");
#if defined(__linux__) || defined(__MACH__)
    pthread_exit(NULL);
    return NULL;
#endif
#ifdef _WIN32
    return 0;
#endif // _WIN32
}

void *udial(void * ptr)
{
    while((!state.salt_got)&&(state.challegecount<MAX_CHA_TRY))
        {
        i=usend(sock,T_CHAPKT);
        bftime=time(NULL);
        if(options.verbose>4)
            printf("[udial] %d bytes sent\n",i);
        while((bftime>time(NULL)-WAIT_TIME)&&(!state.salt_got));
        if(state.salt_got)
            break;
        }
    if(state.challegecount>=MAX_CHA_TRY)
    {
        fprintf(stderr,"[udial] cha fail\n");
        exit(-1);
    }
    if(state.salt_got)
    {
        i=usend(sock,T_LGIPKT);
        if(options.verbose>4)
            printf("[udial] %d bytes sent\n",i);
        while((bftime>time(NULL)-WAIT_TIME)&&(!state.loggedin));
        if(state.loggedin)
            state.salt_got=false;
        else
        {
            fprintf(stderr,"[udial] login fail!\n");
            exit(-1);
        }
    }
#if defined(__linux__) || defined(__MACH__)
    pthread_exit(NULL);
#endif
    return NULL;
}
void *ukplv(void * ptr)
{
    while(state.loggedin)
        {
            i=usend(sock,T_KALPKT);
            if(options.verbose>4)
                printf("[ukplv] %d bytes sent\n",i);
            bftime=time(NULL);
            while((bftime>time(NULL)-WAIT_TIME)&&(!state.kalsuc));
            if(state.kalsuc)
            {
                state.kalsuc=false;
                int protect=0;
                while((state.mcstate<4)&&(protect++<5))
                {
                    state.miscsuc=false;
                    i=usend(sock,T_MSCPKT);
                    if(options.verbose>4)
                        printf("[ukplv] %d bytes sent\n",i);
                    bftime=time(NULL);
                    while((bftime>time(NULL)-WAIT_TIME)&&(!state.miscsuc));

                }
                state.kalsuc=false;
                if(state.mcstate<4)
                {
                    state.loggedin=false;
#if defined(__linux__) || defined(__MACH__)
                    pthread_exit(NULL);
#endif // defined
                    return NULL;
                }
                printf("[ukplv] misc exchange sucess\n");
            }
            else
            {
                state.loggedin=false;
#if defined(__linux__) || defined(__MACH__)
                pthread_exit(NULL);
#endif // defined
                return NULL;
            }

            sleep(20);
        }
#if defined(__linux__) || defined(__MACH__)
    pthread_exit(NULL);
#endif
    return NULL;
}

unsigned int usend(int socket,uint16_t pkttype)
{
    char *buf;
    int16_t i=0;

    switch (pkttype)
    {
    case T_CHAPKT:
        buf=challegepkt();
        i=sizeof(struct dobechapkt);
        break;
    case T_LGIPKT:
        buf=loginpkt();
        if(!options.ror)
            i=sizeof(struct dobelgipkt);
        else
            i=sizeof(struct dobelgipkt)+sizeof(struct rorlgiextinfo)-1+strlen(info.password);
        break;
    case T_KALPKT:
        buf=heartpkt();
        i=sizeof(struct dobekalpkt);
        break;
    case T_LGOPKT:
        buf=logoutpkt();
        i=sizeof(struct dobelgopkt);
        break;
    case T_MSCPKT:
        buf=miscpkt();
        i=DOBEMISC_LENGTH;
        break;
    default:
        fprintf(stderr,"[usend] Unknown packet type 0x%04x!\n",pkttype);
        exit(errno);
    }
#ifdef _DEBUG
    if(options.verbose>4)
        fprintf(stderr,"[usend] sending:\n%s",sprintx((unsigned char *)buf,i));//fake
#endif // _DEBUG
    i=sendto(socket, buf,i, 0, (struct sockaddr *)&state.serveraddr,sizeof(struct sockaddr_in));
    free(buf);
    if(i<=0)
        error("usend");
    return i;
}

int urecv(int socket)
{
    void *buf=malloc(MAX_RECV_PKT);
    int16_t i=0;
    i=recvfrom(socket, (char*)buf,MAX_RECV_PKT, 0, NULL, NULL);
    switch (*(unsigned char *)buf)
    {
    case T_CHRPKT:
        if(i>=sizeof(struct dobechrpkt))
        {
            struct dobechrpkt *chrptr=buf;
            memcpy(state.salt,chrptr->salt,4);
            state.salt_got=true;
#ifdef _DEBUG
            if(options.verbose>4)
                fprintf(stderr,"[urecv] salt is %s\n",sprintx(state.salt,4));
            //printx(state.salt,4);
#endif // _DEBUG
        }
        else
            fprintf(stderr,"[urecv] Invaild cha respond pkt lngth!\n");
        break;
    case T_SUCPKT:
        if(i==DOBELGISUC_LENGTH)
        {
            struct dobesucpkt *sucptr=buf;
            memcpy(state.auth,sucptr->auth,16);
            //get info from ptr
            state.loggedin=true;
        }
        else if(i==DOBELGOSUC_LENGTH)
        {
            printf("[urecv] logged out\n");
            state.loggedin=false;
        }
        else
            fprintf(stderr,"[urecv] Invaild sucess pkt lngth %d!\n",i);
        break;
    case T_FALPKT:
        //fprintf(stderr,"[urecv] login fail");
        state.loggedin=false;
        switch(*(uint8_t*)(buf+4))
        {
        case 0x03:
            fprintf(stderr,"[urecv] login fail - wrong combination\n");
            break;
        case 0x16:
            fprintf(stderr,"[urecv] login fail - wrong mac or ip\n");
            break;
        case 0x01:
            fprintf(stderr,"[urecv] login fail - account already loged in using\n");
            break;
        default:
            fprintf(stderr,"[urecv] login fail - unknown 0x%02X\n",*(uint8_t*)(buf+4));
            break;
        }
        exit(-1);
        break;
    case T_MSGPKT:
        //todo :show
        printf("[urecv] msgpkt:\n");
        break;
    case T_MSCPKT:
        switch(ntohs(((struct dobemscpkt *)buf)->type))
        {
        case MTS_FILE:
            if(options.verbose>3)
                printf("[urecv] got file ,ignore it\n");
        case MTS_ROK:
            state.mcstate=0;
            state.miscsuc=true;
            state.kalsuc=true;
            state.time=((struct dobemscpkt *)buf)->time;
            if(options.verbose>3)
            printf("[urecv] got keep alive resp\n");
            break;
        case MTS_2800:
            state.mcstate=((struct dobemscpkt *)buf)->mctype;
            state.time=((struct dobemscpkt *)buf)->time;
            memcpy(state.ukn1,&((struct dobemscpkt *)buf)->uknown1,2);
            memcpy(state.ukn2,&((struct dobemscpkt *)buf)->mm,4);
            state.miscsuc=true;
            if(options.verbose>3)
                printf("[urecv] got common misc\n");
            break;
        default:
            fprintf(stderr,"[urecv] Unknown misc pkttype: %04X\n",ntohs(((struct dobemscpkt *)buf)->type));
        }

        break;
    default:
        if(options.verbose>1)
            fprintf(stderr,"[urecv] Unknown packet type 0x%02x!,ignore it\n",*(char *)buf);
    }
#ifdef _DEBUG
    if(options.verbose>4)
        fprintf(stderr,"[urecv] receive pkt:\n%s",sprintx(buf,i));
#endif // _DEBUG
    free(buf);
    return i;
}

void usage()
{
    printf("Usage here\n");
    exit(0);
}
