/**
 * This file handles all the Thread Management related activities.
 * This file will create following threads to manage Delta Engine:
 * - WAN traffic
 * - LAN traffic
 * - Telemetry data
 *
 * export LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu/
 * Compile options: gcc -g -o DeltaEngine deltaengine.c -D DEBUG_PRINT -D ENABLE_MUTEX -D BLACKLIST_RANK -Wall -Werror -lpthread `mysql_config --cflags --libs`
 * -D DEBUG_PROFILING will turn on profiling. For now it is only on WAN thread
 * -D DEBUG_PRINT will turn on printing for debug logs on console.
 * -D DEBUG_PACKET will turn on printing for packets on console.
 * -D ENABLE_MUTEX will turn on mutex lock.
 * -D BLACKLIST_RANK will turn on ranking algorithm.
 * Author: Atul / Hari / Madhur
 * new compile option - gcc -g -o de deltaengine.c  -D ENABLE_MUTEX -D BLACKLIST_RANK -D DEBUG_PRINT -Wall -Werror -lpthread -lpcap `mysql_config --cflags --libs`
 *export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
 *
 **/

/* Includes */
#define _GNU_SOURCE
#include <stdio.h>      /* Input/Output */
#include <pthread.h>    /* POSIX Threads */
#include <string.h>     /* String handling */
#include <strings.h>
#include <stdlib.h>     /* General Utilities */
#include <errno.h>      /* Errors */
#include <sys/types.h>  /* Primitive System Data Types */
#include <unistd.h>     /* Symbolic Constants */
#include <sys/socket.h> /* socket functions */
#include <stdbool.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <linux/icmp.h>
#include <mysql.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include "de.h"
#include "deDb.c"
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <semaphore.h>
#include <sched.h>
#include <unistd.h>
#include <fcntl.h>
#include <pcap.h>

#include "de_telemetry.c"

#define BILLION 1000000000L // used to convert the seconds to nanoseconds
#define MAX_BUFFER_POOL_SIZE 100000

typedef struct BufferPool
{
    void *buffer;
    bool inUse;
    unsigned int length;
} BufferPool;
struct BufferPool bufferPoolLAN[MAX_BUFFER_POOL_SIZE];
struct BufferPool bufferPoolWAN[MAX_BUFFER_POOL_SIZE];

#ifdef ENABLE_MUTEX
sem_t semDbInsertLock;
#endif

pcap_t *lan_handle;
pcap_t *wan_handle;
bool isNat = false;
bool isPat = false;
struct timespec timeStamp;
unsigned char ethlan[6], ethwan[6];
MYSQL *conlan, *conwan;
void processLanTrafficPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);
void processWanTrafficPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);


double GetPrintTimeStamp()
{
    clock_gettime(CLOCK_REALTIME, &timeStamp);
    return (BILLION * timeStamp.tv_sec + timeStamp.tv_nsec);
}

#ifdef DEBUG_PACKET
void print_buffer(void *buf, int buflen)
{
    int i;
    unsigned char *pkt = (unsigned char*)buf;
    printf ("\n in print_buffer\n");
    for (i=0; i<buflen; i++)
    {
        printf("%02x ", pkt[i]);
        printf(" ");
    }
}
#endif

/*
 1 is multicast pkt and 0 is not. For now just make two distinct functions so they don't have to share the same function
*/
unsigned int multicast_pkt_check_wan(__be32 ip_addr)
{
    // the MSB is at the right most byte and we have to check the first 4 bits of the MSB (1110)
    if(((ip_addr & 0x000000e0)) == 0xe0) // check if the first 4 bits is 1110 (14) of the MSB
    {
        #ifdef DEBUG_MULTICAST
        printf("\nMulticast the IP address dest addr :%u.%u.%u.%u\n ", ip_addr & 0xff, ip_addr>>8 & 0xff, ip_addr>>16 & 0xff, ip_addr>>24 & 0xff);
        #endif
        return 1;
    }
    return 0;
}
unsigned int multicast_pkt_check_lan(__be32 ip_addr)
{
    // the MSB is at the right most byte and we have to check the first 4 bits of the MSB (1110)
    if(((ip_addr & 0x000000e0)) == 0xe0) // check if the first 4 bits is 1110 (14) of the MSB
    {
        #ifdef DEBUG_MULTICAST
        printf("\nMulticast the IP address dest addr :%u.%u.%u.%u\n ", ip_addr & 0xff, ip_addr>>8 & 0xff, ip_addr>>16 & 0xff, ip_addr>>24 & 0xff);
        #endif
        return 1;

    }
    return 0;
}
/*
 * a value of 1 is a broadcast IP and 0 is NOT . Make two distinct functions so they don't have to share the function across threads. Todo - find a better way to do this
 */
unsigned int broadcast_pkt_check_wan(__be32 ip_addr)
{
    /* get interface mask address */
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *netmask;

    //printf ("\n broadcast pkt check:%u", ip_addr);
    getifaddrs (&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr->sa_family==AF_INET)
        {
            //sa = (struct sockaddr_in *) ifa->ifa_addr;
            netmask = (struct sockaddr_in *) ifa->ifa_netmask;
            // addr = inet_ntoa(sa->sin_addr);
            __be32 broadcastAddress = (ip_addr | (~(netmask->sin_addr.s_addr)));
            // printf("Interface: %s\tBAddress: %u DAddr %u \n", ifa->ifa_name, (int) broadcastAddress, (int)ip_addr );
            if( broadcastAddress == ip_addr)
            {
                #ifdef DEBUG_BROADCAST
                //printf("\nSAME Interface: %s\tBAddress: %u DAddr %u \n", ifa->ifa_name, (int) broadcastAddress, (int)ip_addr );
                #endif
                freeifaddrs(ifap);
                return 1;
            }
        }
    }
    freeifaddrs(ifap);
    return 0;
}
unsigned int broadcast_pkt_check_lan(__be32 ip_addr)
{
    /* get interface mask address */
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *netmask;

    //printf ("\n broadcast pkt check:%u", ip_addr);
    getifaddrs (&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr->sa_family==AF_INET)
        {
            //sa = (struct sockaddr_in *) ifa->ifa_addr;
            netmask = (struct sockaddr_in *) ifa->ifa_netmask;
            // addr = inet_ntoa(sa->sin_addr);
            __be32 broadcastAddress = (ip_addr | (~(netmask->sin_addr.s_addr)));
            // printf("Interface: %s\tBAddress: %u DAddr %u \n", ifa->ifa_name, (int) broadcastAddress, (int)ip_addr );
            if( broadcastAddress == ip_addr)
            {
                #ifdef DEBUG_BROADCAST
                //printf("\nSAME Interface: %s\tBAddress: %u DAddr %u \n", ifa->ifa_name, (int) broadcastAddress, (int)ip_addr );
                #endif
            freeifaddrs(ifap);
            return 1;
            }
        }
    }
    freeifaddrs(ifap);
    return 0;
}

// DNS pkt can be of TCP or UDP protocol
// for now we shouldn't get the pkt on the LAN that are DNS pkt as we will ignore them on WAN
// but later have to add LAN and WAN side separately
bool dns_pkt_check_udp_wan(struct udphdr *udph)
{
    bool  iRet=false;
    if ((ntohs(udph->dest) == DNS_PORT_NUM) || (ntohs(udph->source) == DNS_PORT_NUM))
        iRet = true;
    return iRet;
}

bool dns_pkt_check_udp_lan(struct udphdr *udph)
{
    bool  iRet=false;
    if ((ntohs(udph->dest) == DNS_PORT_NUM) || (ntohs(udph->source) == DNS_PORT_NUM))
        iRet = true;
    return iRet;
}
bool dns_pkt_check_tcp_wan(struct tcphdr *tcph)
{
    bool  iRet=false;
    if ((ntohs(tcph->dest) == DNS_PORT_NUM) || (ntohs(tcph->source) == DNS_PORT_NUM))
        iRet = true;
    return iRet;
}

bool dns_pkt_check_tcp_lan(struct tcphdr *tcph)
{
    bool  iRet=false;
    if ((ntohs(tcph->dest) == DNS_PORT_NUM) || (ntohs(tcph->source) == DNS_PORT_NUM))
        iRet = true;
    return iRet;
}

// Below are functions to create the query string for In memory DB access. 
bool  create_query_string_tcp_wan(struct iphdr *iph,  struct tcphdr *tcph, unsigned int table_type, char *query)
{
      bool iRet = true;
      if (isPat)
      {
         switch (table_type) {
               case WHITE_LIST:
                    sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND protocol = 'tcp' AND tableType = 'white';", iph->saddr);
                    break;
               case BLACK_LIST:
                    sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND protocol = 'tcp' AND tableType = 'black';", iph->saddr);
                    break;
               case STATE_LIST:
                    sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND protocol = 'tcp' AND tableType = 'state';", iph->saddr);
                    break;
                default:
                    iRet = false;
                    break;
         }
      }
      else if (isNat)
      {
         switch (table_type) {
               case WHITE_LIST:
                    sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstPort = %hu AND protocol = 'tcp' AND tableType = 'white';", iph->saddr, tcph->dest);
                    break;
               case BLACK_LIST:
                    sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstPort = %hu AND protocol = 'tcp' AND tableType = 'black';", iph->saddr, tcph->dest);
                    break;
               case STATE_LIST:
                    sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstPort = %hu AND protocol = 'tcp' AND tableType = 'state';", iph->saddr, tcph->dest);
                    break;
                default:
                    iRet = false;
                    break;
         }
      }
      else
      {
           switch (table_type) {
               case WHITE_LIST:
                  sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstIP = %u AND dstPort = %hu AND protocol = 'tcp' AND tableType = 'white';", iph->saddr , iph->daddr, tcph->dest);
                  break;
               case BLACK_LIST:
                  sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstIP = %u AND dstPort = %hu AND protocol = 'tcp' AND tableType = 'black';", iph->saddr , iph->daddr, tcph->dest);
                   break;
               case STATE_LIST:
                  sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstIP = %u AND dstPort = %hu AND protocol = 'tcp' AND tableType = 'state';", iph->saddr , iph->daddr, tcph->dest);
                  break;
                default:
                    iRet = false;
                  break;
           }
      }
      return iRet;
}
bool  create_query_string_tcp_lan(struct iphdr *iph,  struct tcphdr *tcph, unsigned int table_type, char *query)
{
      bool iRet = true;
      if (isPat)
      {
         switch (table_type) {
               case WHITE_LIST:
                    sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND protocol = 'tcp' AND tableType = 'white';", iph->saddr);
                    break;
               case BLACK_LIST:
                    sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND protocol = 'tcp'  AND tableType = 'black';", iph->saddr);
                    break;
               case STATE_LIST:
                    sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND protocol = 'tcp'  AND tableType = 'state';", iph->saddr);
                    break;
                default:
                    iRet = false;
                    break;
         }
      }
      else if (isNat)
      {
         switch (table_type) {
               case WHITE_LIST:
                    sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstPort = %hu AND protocol = 'tcp' AND tableType = 'white';", iph->saddr, tcph->dest);
                    break;
               case BLACK_LIST:
                    sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstPort = %hu AND protocol = 'tcp' AND tableType = 'black';", iph->saddr, tcph->dest);
                    break;
               case STATE_LIST:
                    sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstPort = %hu AND protocol = 'tcp' AND tableType = 'state';", iph->saddr, tcph->dest);
                    break;
                default:
                    iRet = false;
                    break;
         }
      }
      else
      {
           switch (table_type) {
               case WHITE_LIST:
                  sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstIP = %u AND dstPort = %hu AND protocol = 'tcp' AND tableType = 'white';", iph->saddr , iph->daddr, tcph->dest);
                  break;
               case BLACK_LIST:
                  sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstIP = %u AND dstPort = %hu AND protocol = 'tcp' AND tableType = 'black';", iph->saddr , iph->daddr, tcph->dest);
                   break;
               case STATE_LIST:
                  sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstIP = %u AND dstPort = %hu AND protocol = 'tcp' AND tableType = 'state';", iph->saddr , iph->daddr, tcph->dest);
                  break;
                default:
                    iRet = false;
                  break;
           }
      }
      return iRet;
}
bool  create_query_string_udp_wan(struct iphdr *iph,  struct udphdr *udph, unsigned int table_type, char *query)
{
      bool iRet = true;
      if (isPat)
      {
         switch (table_type) {
               case WHITE_LIST:
                    sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND protocol = 'udp' AND tableType = 'white';", iph->saddr);
                    break;
               case BLACK_LIST:
                    sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND protocol = 'udp' AND tableType = 'black';", iph->saddr);
                    break;
               case STATE_LIST:
                    sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND protocol = 'udp' AND tableType = 'state';", iph->saddr);
                    break;
                default:
                    iRet = false;
                    break;
         }
      }
      else if (isNat)
      {
         switch (table_type) {
               case WHITE_LIST:
                    sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstPort = %hu AND protocol = 'udp' AND tableType = 'white';", iph->saddr, udph->dest);
                    break;
               case BLACK_LIST:
                    sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstPort = %hu AND protocol = 'udp' AND tableType = 'black';", iph->saddr, udph->dest);
                    break;
               case STATE_LIST:
                    sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstPort = %hu AND protocol = 'udp' AND tableType = 'state';", iph->saddr, udph->dest);
                    break;
                default:
                    iRet = false;
                    break;
         }
      }
      else
      {
           switch (table_type) {
               case WHITE_LIST:
                  sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstIP = %u AND dstPort = %hu AND protocol = 'udp' AND tableType = 'white';", iph->saddr , iph->daddr, udph->dest);
                  break;
               case BLACK_LIST:
                  sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstIP = %u AND dstPort = %hu AND protocol = 'udp' AND tableType = 'black';", iph->saddr , iph->daddr, udph->dest);
                   break;
               case STATE_LIST:
                  sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstIP = %u AND dstPort = %hu AND protocol = 'udp' AND tableType = 'state';", iph->saddr , iph->daddr, udph->dest);
                   break;
                  break;
                default:
                    iRet = false;
                  break;
           }
      }
      return iRet;
}
bool  create_query_string_udp_lan(struct iphdr *iph,  struct udphdr *udph, unsigned int table_type, char *query)
{
      bool iRet = true;
      if (isPat)
      {
         switch (table_type) {
               case WHITE_LIST:
                    sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND protocol = 'udp' AND tableType = 'white';", iph->saddr);
                    break;
               case BLACK_LIST:
                    sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND protocol = 'udp' AND tableType = 'black';", iph->saddr);
                    break;
               case STATE_LIST:
                    sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND protocol = 'udp' AND tableType = 'state';", iph->saddr);
                    break;
                default:
                    iRet = false;
                    break;
         }
      }
      else if (isNat)
      {
         switch (table_type) {
               case WHITE_LIST:
                    sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstPort = %hu AND protocol = 'udp' AND tableType = 'white';", iph->saddr, udph->dest);
                    break;
               case BLACK_LIST:
                    sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstPort = %hu AND protocol = 'udp' AND tableType = 'black';", iph->saddr, udph->dest);
                    break;
               case STATE_LIST:
                    sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstPort = %hu AND protocol = 'udp' AND tableType = 'state';", iph->saddr, udph->dest);
                    break;
                default:
                    iRet = false;
                    break;
         }
      }
      else
      {
           switch (table_type) {
               case WHITE_LIST:
                  sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstIP = %u AND dstPort = %hu AND protocol = 'udp' AND tableType = 'white';", iph->saddr , iph->daddr, udph->dest);
                  break;
               case BLACK_LIST:
                  sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstIP = %u AND dstPort = %hu AND protocol = 'udp' AND tableType = 'black';", iph->saddr , iph->daddr, udph->dest);
                   break;
               case STATE_LIST:
                  sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstIP = %u AND dstPort = %hu AND protocol = 'udp' AND tableType = 'state';", iph->saddr , iph->daddr, udph->dest);
                  break;
                default:
                    iRet = false;
                  break;
           }
      }
      return iRet;
}

// check the static IP list config for TCP protocol
int check_static_ip_config_tcp(MYSQL *con, struct iphdr *iph, struct tcphdr *tcph)
{   char query[300];
    int result =0;
   // check the static White & Black List        // put a check for PAT/NAT and plain IP cases 
    if (isPat)
        sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND protocol = 'tcp' AND mode = 'static' AND tableType IN ('white','black');", iph->saddr);
     else if (isNat)
        sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstPort = %hu AND protocol = 'tcp ' AND mode = 'static' AND tableType IN ('white','black');", iph->saddr, tcph->dest);
     else  // Plain Vanilla case         
        sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstIP = %u AND dstPort = %hu AND protocol = 'tcp' AND mode = 'static' AND tableType IN ('white','black');", iph->saddr , iph->daddr, tcph->dest);
     Count(con, query, &result);
      #ifdef DEBUG_PRINT
      printf("\nWAN TCP:: Static IP list Query: %s Matchfound:%d\n", query, result);
     #endif
   return result;
}

// check the static IP list config for UDP protocol
int check_static_ip_config_udp(MYSQL *con, struct iphdr *iph, struct udphdr *udph)
{
   char query[300];
    int result =0;
   // check the static White List first 
    if (isPat)
        sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND protocol = 'udp' AND mode = 'static' AND tableType IN ('white','black');", iph->saddr );
     else if (isNat)
        sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstPort = %hu AND protocol = 'udp' AND mode = 'static' AND tableType IN ('white','black');", iph->saddr, udph->dest);
     else
         sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstIP = %u AND dstPort = %hu AND protocol = 'udp' AND mode = 'static' AND tableType IN ('white','black');", iph->saddr , iph->daddr, udph->dest);

     Count(con, query, &result);
      #ifdef DEBUG_PRINT
      printf("\nWAN UDP:: Static IP list Query: %s Matchfound:%d\n", query, result);
     #endif
   return result;
}

// check the dynamic IP list config for TCP protocol
int check_dynamic_ip_config_tcp(MYSQL *con, struct iphdr *iph, struct tcphdr *tcph)
{   char query[300];
    int result =0;
   // check the static White  & Black List        // put a check for PAT/NAT and plain IP cases 
    if (isPat)
        sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND protocol = 'tcp' AND mode = 'dynamic' AND tableType IN ('white','black') AND (timeStamp > DATE_SUB(SYSDATE(6), INTERVAL 1000000 MICROSECOND));", iph->saddr);
     else if (isNat)
        sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstPort = %hu AND protocol = 'tcp ' AND mode = 'dynamic' AND tableType IN ('white','black') AND (timeStamp > DATE_SUB(SYSDATE(6), INTERVAL 1000000 MICROSECOND));", iph->saddr, tcph->dest);
     else  // Plain Vanilla case         
        sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstIP = %u AND dstPort = %hu AND protocol = 'tcp' AND mode = 'dynamic' AND tableType IN ('white','black') AND (timeStamp > DATE_SUB(SYSDATE(6), INTERVAL 1000000 MICROSECOND));", iph->saddr , iph->daddr, tcph->dest);
     Count(con, query, &result);
      #ifdef DEBUG_PRINT
      printf("\nWAN TCP:: Dynamic IP list Query: %s Matchfound:%d\n", query, result);
     #endif
   return result;
}

// check the dynamic IP list config for UDP protocol
int check_dynamic_ip_config_udp(MYSQL *con, struct iphdr *iph, struct udphdr *udph)
{
   char query[300];
    int result =0;
   // check the static White & Black List 
    if (isPat)
        sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND protocol = 'udp' AND mode = 'dynamic' AND tableType IN ('white','black') AND (timeStamp > DATE_SUB(SYSDATE(6), INTERVAL 1000000 MICROSECOND));", iph->saddr );
     else if (isNat)
        sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstPort = %hu AND protocol = 'udp' AND mode = 'dynamic' AND tableType IN ('white','black') AND (timeStamp > DATE_SUB(SYSDATE(6), INTERVAL 1000000 MICROSECOND));", iph->saddr, udph->dest);
     else
         sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstIP = %u AND dstPort = %hu AND protocol = 'udp' AND mode = 'dynamic' AND tableType IN ('white','black') AND timeStamp > DATE_SUB(SYSDATE(6), INTERVAL 1000000 MICROSECOND);", iph->saddr , iph->daddr, udph->dest);

     Count(con, query, &result);
      #ifdef DEBUG_PRINT
      printf("\nWAN UDP:: Dynamic IP list Query: %s Matchfound:%d\n", query, result);
     #endif
   return result;
}

/**
 * processWanTraffic is used as the start routine for the thread
 * This thread is for WAN traffic. We will detect the traffic that is coming and
 * going out of this interface.
 * We are generally interested only in the traffic that is coming in i.e a request
 * pkt. Also track if it is coming in or leaving the interface.
 * Ethernet header has the following -
Preamble: 8 bytes
Destination mac: 6 bytes
Source mac: 6 bytes
Type/length: 2 bytes
Data: 46-1500 bytes
 * IP header is at byte 22 bytes
 */
void processWanTraffic()
{
    struct ethhdr *ethh;
    struct iphdr  *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    const void *buffer;
    MYSQL *con = NULL;
    char query[300];
    bool isIncoming = false;
    int result = 0;
    int counter = 0;
    int iDirection = 1; // this is to store the result of memcmp of ethernet dest/source.

    int cnt = 0;
    struct timeval tv;

    #ifdef DEBUG_PROFILING
    double  accum = 0;
    struct timespec requestStart, requestEnd;
    #endif
    con = conwan;
    printf("\n Inside WAN Traffic\n");
     while (1)
     {        
          if (counter >= MAX_BUFFER_POOL_SIZE)
          {
              counter = 0;
          }

         if (bufferPoolWAN[counter].inUse)
         {
     //       printf("processWanTraffic:: Counter-> %d, inUse-> %d\n", counter, bufferPoolWAN[counter].inUse);
            buffer = bufferPoolWAN[counter].buffer; 

	    #ifdef DEBUG_PROFILING
	    clock_gettime(CLOCK_REALTIME, &requestStart);
	    #endif
	    #ifdef DEBUG_PACKET
	    /* get all the headers here from the buffer */
	    print_buffer(buffer, header->len);
	    #endif

	    ethh = (struct ethhdr *)buffer;
	    iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
	    iDirection = memcmp(ethh->h_dest, ethwan, 6);
	    if (!iDirection)
		isIncoming = true;
     /*       if (iph->protocol == 6)
            {
                tcph = (struct tcphdr *)(buffer+ sizeof(struct ethhdr)+iph->ihl*4);
                printf ("\nWAN:Algorithm details: Time->%lf: SrcIP-> %u DstIP-> %u SrcPort-> %d DstPort-> %d TCP SYN: %d Protocol-> %d isIncoming-> %d CNT-> %d\n", GetPrintTimeStamp(), iph->saddr, iph->daddr, tcph->source, tcph->dest, tcph->syn, iph->protocol, isIncoming, counter); 
            }
    */

	    if (isIncoming )
	    {
		switch (iph->protocol)
		{
		    case IPPROTO_ICMP:
			break;
		    case IPPROTO_TCP:
			tcph = (struct tcphdr *)(buffer+ sizeof(struct ethhdr)+iph->ihl*4);
     /*                   printf ("\nWAN:TCP Algorithm details: Time->%lf: SrcIP-> %u DstIP-> %u SrcPort-> %d DstPort-> %d TCP SYN: %d CNT-> %d\n", GetPrintTimeStamp(), iph->saddr, iph->daddr, tcph->source, tcph->dest, tcph->syn, counter); */
			if (dns_pkt_check_tcp_wan(tcph))
			{
			    #ifdef DEBUG_PACKET
			    printf("\n WAN: DNS TCP pkt #:%d :%d\n", ntohs(tcph->source), ntohs(tcph->dest));
			    #endif
                            bufferPoolWAN[counter].inUse = false;
                            counter++;
                            continue;
			}
            // Telemetry stuff 
            gettimeofday(&tv, NULL);
            pktInfoDataWan[cnt].srcIP     = iph->saddr;
            pktInfoDataWan[cnt].dstIP     = iph->daddr;
            pktInfoDataWan[cnt].srcPort   = tcph->source;
            pktInfoDataWan[cnt].dstPort   = tcph->dest;
            pktInfoDataWan[cnt].protocol  = iph->protocol;
            pktInfoDataWan[cnt].pktLen    = bufferPoolWAN[counter].length;
            pktInfoDataWan[cnt].direction = wan;
            pktInfoDataWan[cnt].timestamp = tv.tv_sec;
            if (msgsnd(msgQueueId, &pktInfoDataWan[cnt], sizeof(PktInfo)-8, 0) == -1)
            {
                    printf("msg send failed\n");
            }
            else
            {
                    #ifdef DEBUG_PRINT
                    printf("WAN: msg send success\n");
                    #endif
            }

			/* check for originating traffic */
			if (tcph->syn)
			{
			    #ifdef DEBUG_PRINT
			    printf("\nWAN::Detected TCP Syn packet.\n");
			    #endif

			    if (isIncoming)  // Incoming TCP SYN packet.
			    {
				#ifdef ENABLE_MUTEX
				// Semaphore lock.
				sem_wait(&semDbInsertLock);
				#endif
				if((check_static_ip_config_tcp(con, iph, tcph)==0) && (check_dynamic_ip_config_tcp(con, iph, tcph)==0))
				{
				   create_query_string_tcp_wan(iph,  tcph, STATE_LIST, query);
				   Count(con, query, &result);
				    if(result == 0)
				    {
					/* this is the first time syn packet is entering. Add it to state machine */
					sprintf(query, "INSERT INTO pi.DeltaList (timeStamp, srcIP, dstIP, srcPort, dstPort, protocol, direction, mode, tableType) values (sysdate(6), %u, %u, %hu, %hu, 'tcp', 'wan', 'dynamic', 'state');", iph->saddr, iph->daddr, tcph->source, tcph->dest);
					#ifdef DEBUG_PRINT
					printf("\nWAN::Time: %lf: Inserting into State table: %s", GetPrintTimeStamp(), query);
					#endif
					Insert(con, query);
				    }
				    else
				    {
					#ifdef DEBUG_PRINT
					  printf("\nWAN::Match found in State List: State Query: %s\n", query);
					#endif
				    }
				}
				#ifdef ENABLE_MUTEX
				sem_post(&semDbInsertLock);
				#endif
			    }                        
			}
			else
			{
			    #ifdef IGNORE
			    printf ("\nWAN::***All other traffic \n");
			    #endif // LATER
			}
			break;
		    case IPPROTO_UDP:
			udph = (struct udphdr *)(buffer+ sizeof(struct ethhdr)+iph->ihl*4);
                        /* printf ("\nWAN:UDP Algorithm details: Time-> %lf: SrcIP-> %u DstIP-> %u SrcPort-> %d DstPort-> %d CNT-> %d\n", GetPrintTimeStamp(), iph->saddr, iph->daddr, udph->source, udph->dest,  counter); */

			if (dns_pkt_check_udp_wan(udph))
			{
			    #ifdef DEBUG_PACKET
			    printf ("\nWAN::UDP DNS pkt :%d :%d", ntohs(udph->source), ntohs(udph->dest));
			    #endif
                            bufferPoolWAN[counter].inUse = false;
                            counter++;
                            continue;
			}

			// Like TCP check INCOMING (WAN->LAN) only for Beta1
			// NOTE: this code should  be merged LATER.. with TCP case. Just change the protocol type
			if (isIncoming)
			{
			    #ifdef ENABLE_MUTEX
			    // Semaphore lock.
			    sem_wait(&semDbInsertLock);
			    #endif
			    if( ( check_static_ip_config_udp(con, iph, udph) ==0) && ( check_dynamic_ip_config_udp(con, iph, udph) ==0))
			    {
				 create_query_string_udp_wan(iph,  udph, STATE_LIST, query);
				 Count(con, query, &result);
				 if(result == 0)
				 {
				       /* this is the first time packet is entering. Add it to state machine */
				      sprintf(query, "INSERT INTO pi.DeltaList (timeStamp, srcIP, dstIP, srcPort, dstPort, protocol, direction, mode, tableType) values (sysdate(6), %u, %u, %hu, %hu, 'udp', 'wan', 'dynamic', 'state');", iph->saddr, iph->daddr, udph->source, udph->dest);
					#ifdef DEBUG_PRINT
					printf("\nWAN::Inserting into State table: %s", query);
					#endif
					Insert(con, query);
				 }
				 else
				 {
				    #ifdef DEBUG_PRINT
				    printf("\nWAN::Match found in State: State Query: %s\n", query);
				    #endif

				}
			    }
			    #ifdef ENABLE_MUTEX
			    sem_post(&semDbInsertLock);
			    #endif 
			} 
			break;
		    default:
			break;
		}
	    }
	    #ifdef DEBUG_PROFILING
	    clock_gettime(CLOCK_REALTIME, &requestEnd);
	    accum = ( requestEnd.tv_sec - requestStart.tv_sec )*BILLION + ( requestEnd.tv_nsec - requestStart.tv_nsec ) ;
	    printf("WAN THREAD: PKT size:%d bytes, %lf nseconds\n", length, accum );
	    #endif
              bufferPoolWAN[counter].inUse = false;
              bufferPoolWAN[counter].length = 0;
              memset(bufferPoolWAN[counter].buffer, 0, (ETH_FRAME_LEN+1));
           }
           counter++;
          
           if (cnt++ >= MAX_BUFFER_POOL_SIZE)
           {
               // Respin the buffer pool.
               cnt = 0;
           }
     }
     pthread_exit(0); /* exit */
}

void processWanBufferTraffic()
{
       struct bpf_program fp;          /* The compiled filter expression */
        //bpf_u_int32 mask;               /* The netmask of our sniffing device */
        //bpf_u_int32 net;                /* The IP of our sniffing device */
        char errbuf[PCAP_ERRBUF_SIZE];
        char filter_exp[50];
        int cnt = 0;
        char dev[5];
        
       sprintf(filter_exp, "ether dst %2x:%2x:%2x:%2x:%2x:%2x", ethwan[0], ethwan[1], ethwan[2],ethwan[3],ethwan[4],ethwan[5]);
        //char filter_exp[] = "ether dst 00:50:56:85:76:66";
        printf("PCAP Filter Exp: %s\n", filter_exp);
        strcpy (dev, readPiOptions(conwan, "WAN_INTERFACE"));

        for (cnt = 0; cnt < MAX_BUFFER_POOL_SIZE; cnt++)
        {
        if ( (bufferPoolWAN[cnt].buffer = (void*) malloc (ETH_FRAME_LEN+1) ) == NULL )
        {
            printf ( "Cannot allocate memory\n" );
            pthread_exit(0); // exit
        }
        bufferPoolWAN[cnt].inUse = false;
        bufferPoolWAN[cnt].length = 0;
        memset (bufferPoolWAN[cnt].buffer, 0, (ETH_FRAME_LEN+1));
        }
        printf("WAN_INTERFACE-> %s\n", dev);
#if 0
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
        {
                 printf( "Can't get netmask for device %s\n", dev);
                 net = 0;
                 mask = 0;
                 pthread_exit(0); /* exit */
                 return;
        }
#endif
        //wan_handle = pcap_open_live(dev, 1500,1,1000,errbuf);
        wan_handle = pcap_open_live(dev, 65535,1,1000,errbuf);
        if (pcap_compile(wan_handle, &fp, filter_exp, 0, 0) == -1)
        {
                printf( "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(wan_handle));
                pthread_exit(0); /* exit */
                return ;
        }
        if (pcap_setfilter(wan_handle, &fp) == -1)
        {
             printf( "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(wan_handle));
              pthread_exit(0); /* exit */
             return ;
        }
    printf ("\n Inside WanBuffer pcap \n");
        //pcap_loop(handle, -1, process_packet, (u_char*) 0);
        pcap_loop(wan_handle, -1, processWanTrafficPacket, NULL);

    printf ("\n END of  WanBuffer pcap \n");
       pthread_exit(0); /* exit */
        return ;
}

void processLanBufferTraffic()
{
        struct bpf_program fp;          /* The compiled filter expression */
        //bpf_u_int32 mask;               /* The netmask of our sniffing device */
        //bpf_u_int32 net;                /* The IP of our sniffing device */
        char errbuf[PCAP_ERRBUF_SIZE];
        char filter_exp[50];
        int cnt = 0;
        char dev[5];
        
        //char filter_exp[] = "ether src 00:50:56:85:2d:87";
        sprintf(filter_exp, "ether src %x:%x:%x:%x:%x:%x", ethlan[0], ethlan[1], ethlan[2],ethlan[3],ethlan[4],ethlan[5]);
        printf("PCAP Filter Exp: %s\n", filter_exp);
        strcpy (dev, readPiOptions(conlan, "LAN_INTERFACE"));
        printf("\nLAN_INTERFACE-> %s\n", dev);

        for (cnt = 0; cnt < MAX_BUFFER_POOL_SIZE; cnt++)
        {
        if ( (bufferPoolLAN[cnt].buffer = (void*) malloc (ETH_FRAME_LEN+1) ) == NULL )
        {
            printf ( "Cannot allocate memory\n" );
            pthread_exit(0); // exit
        }
        bufferPoolLAN[cnt].inUse = false;
        bufferPoolLAN[cnt].length = 0;
        memset (bufferPoolLAN[cnt].buffer, 0, (ETH_FRAME_LEN+1));
        }
#if 0
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
        {
                 printf("Can't get netmask for device %s\n", dev);
                 net = 0;
                 mask = 0;
                pthread_exit(0); /* exit */
                return;
        }
#endif
        //lan_handle = pcap_open_live(dev, 1500,1,1000,errbuf);
        lan_handle = pcap_open_live(dev, 65535,1,1000,errbuf);
       // pcap_compile() the net is needed only for broadcast pkt on that interface and we anyways ignore Bcast pkts so 
       // it should be OK. 
        if (pcap_compile(lan_handle, &fp, filter_exp, 0, 0) == -1)
        {
                printf("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(lan_handle));
                pthread_exit(0); /* exit */
                return ;
        }
        if (pcap_setfilter(lan_handle, &fp) == -1)
        {
                printf("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(lan_handle));
                pthread_exit(0); /* exit */
                return ;
        }
    printf ("\n Inside LanBuffer pcap \n");
        pcap_loop(lan_handle, -1, processLanTrafficPacket, NULL);

    printf ("\n END of  LanBuffer pcap \n");
        pthread_exit(0); /* exit */

        return ;
}

void processWanTrafficPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    struct ethhdr *ethh;
    struct iphdr  *iph;
    //struct tcphdr *tcph;
    int static wcnt;
    int pkt_len=0;

         if (wcnt >= MAX_BUFFER_POOL_SIZE)
         {
            #ifdef DEBUG_PRINT
            printf ("\n WAN BUFFER FULL:: Count:%d\n",wcnt);
            #endif
            wcnt = 0;
         }
        if (!bufferPoolWAN[wcnt].inUse)
        {
            ethh = (struct ethhdr *)buffer;
            iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
     //       tcph = (struct tcphdr *) (buffer + sizeof(struct ethhdr) + iph->ihl*4);
            if (ntohs(ethh->h_proto)==ETH_P_ARP)
            {
                return;
            }

            // look for pkts that are destined for eth0 (WAN) side of FW
            if (broadcast_pkt_check_wan(iph->daddr) || multicast_pkt_check_wan(iph->daddr))
            {
                // if broadcast or multicast IP pkt just ignore processing
                return;
            }
            if ((iph->saddr == htonl(INADDR_LOOPBACK)) || (iph->daddr == htonl(INADDR_LOOPBACK)))
            {
                return;
            }
            if (header->len < ETH_FRAME_LEN) 
                 pkt_len = header->len;
            else 
                  pkt_len = ETH_FRAME_LEN;
            memcpy(bufferPoolWAN[wcnt].buffer, (const void *)buffer, pkt_len);
	    bufferPoolWAN[wcnt].inUse = true;
            bufferPoolWAN[wcnt].length = pkt_len;  
          //  if (iph->protocol == 6)
           // printf ("\nWAN: Copying buffer Time: %lf: Buffer Packet details: :SrcIP-> %u DstIP-> %u  CNT-> %d, SYN:%d InUse-> %d \n", GetPrintTimeStamp(), iph->saddr, iph->daddr, wcnt,tcph->syn, bufferPoolWAN[wcnt].inUse);
          } 
        
            wcnt++;
     
}

void processLanTrafficPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    struct ethhdr *ethh;
    struct iphdr  *iph;
    int static cnt;
    int pkt_len = 0;
       if (cnt >= MAX_BUFFER_POOL_SIZE)
       {
         #ifdef DEBUG_PRINT
         printf ("\n LAN BUFFER FULL:: Count:%d\n",cnt);
         #endif
         cnt = 0;
       }
        if (!bufferPoolLAN[cnt].inUse)
        {
            ethh = (struct ethhdr *)buffer;
            iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
            if (ntohs(ethh->h_proto)==ETH_P_ARP)
            {
                return;
            }

            // look for pkts that are destined for eth0 (WAN) side of FW
            if (broadcast_pkt_check_lan(iph->daddr) || multicast_pkt_check_lan(iph->daddr))
            {
                // if broadcast or multicast IP pkt just ignore processing
                return;
            }
            if ((iph->saddr == htonl(INADDR_LOOPBACK)) || (iph->daddr == htonl(INADDR_LOOPBACK)))
            {
                return;
            }
            if (header->len < ETH_FRAME_LEN)
                 pkt_len = header->len;
            else                  
                 pkt_len = ETH_FRAME_LEN;
            memcpy(bufferPoolLAN[cnt].buffer, (const void *)buffer, pkt_len);
            // printf ("\nLAN: Copying buffer Time: %lf: Buffer Packet details: :SrcIP-> %u DstIP-> %u CNT-> %d\n", GetPrintTimeStamp(), iph->saddr, iph->daddr, cnt); 
	    bufferPoolLAN[cnt].inUse = true;
	    bufferPoolLAN[cnt].length = pkt_len;
          }
            cnt++;
}

void processLanTraffic()
{
    struct ethhdr *ethh;
    struct iphdr  *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    MYSQL *con = conlan;
    char query[300] = "";
    bool isOutgoing = false;
    int result = 0;
    int iDirection = 1; // to decide which direction pkt is coming/leaving
    bool processAgain = false;
    int counter = 0;
    void *buffer;
   
    int cnt = 0;
    struct timeval tv;

    printf("\n Lan Thread started");
     #ifdef DEBUG_PACKET
     printf ("\nLAN::ETH MAC %x %x %x %x %x %x", ethlan[0], ethlan[1], ethlan[2], ethlan[3], ethlan[4], ethlan[5]);
     #endif
     while (1)
     {        
        if (counter >= MAX_BUFFER_POOL_SIZE)
        {
            counter = 0;
        }

         if (bufferPoolLAN[counter].inUse)
         {
            buffer = bufferPoolLAN[counter].buffer; 
	    #ifdef DEBUG_PACKET
	    /* get all the headers here from the buffer */
	    print_buffer(buffer, header->len);
	    #endif
	    ethh = (struct ethhdr *)buffer;
	    iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
	
            iDirection = memcmp(ethh->h_source, ethlan, 6);
            if (!iDirection)
                isOutgoing = true;
            if (isOutgoing)  //later we will add Incoming as well here
            {
		/* we have taken care of only TCP, but there can  be UDP, ICMP, IGMP(multicast) */
		switch (iph->protocol)
		{
		    case IPPROTO_ICMP:
			break;
		    case IPPROTO_TCP:
			tcph = (struct tcphdr *)(buffer+ sizeof(struct ethhdr)+iph->ihl*4);
             //           printf ("\nLAN:Algorithm details: Time-> %lf: SrcIP-> %u DstIP-> %u SrcPort-> %d DstPort-> %d TCP SYN: %d CNT-> %d\n", GetPrintTimeStamp(), iph->saddr, iph->daddr, tcph->source, tcph->dest, tcph->syn, counter);
			if (dns_pkt_check_tcp_lan(tcph))
			{
//			    printf("\n LAN:: TCP DNS pkt #:%d :%d", tcph->source, tcph->dest);
			    #ifdef DEBUG_PACKET
			    printf("\n LAN:: TCP DNS pkt #:%d :%d", ntohs(tcph->source), ntohs(tcph->dest));
			    #endif
                            bufferPoolLAN[counter].inUse = false;
                            counter++;
			    continue;
			}
           
            // Telemetry stuff   
            gettimeofday(&tv, NULL);
            pktInfoDataLan[cnt].srcIP     = iph->saddr;
            pktInfoDataLan[cnt].dstIP     = iph->daddr;
            pktInfoDataLan[cnt].srcPort   = tcph->source;
            pktInfoDataLan[cnt].dstPort   = tcph->dest;
            pktInfoDataLan[cnt].protocol  = iph->protocol;
            pktInfoDataLan[cnt].pktLen    = bufferPoolLAN[counter].length;
            pktInfoDataLan[cnt].direction = lan;
            pktInfoDataLan[cnt].timestamp = tv.tv_sec;
            #ifdef DEBUG_PACKET
            printf("\nLAN: Updating telemetry from LAN.\n");
            #endif
            if (msgsnd(msgQueueId, &pktInfoDataLan[cnt], sizeof(PktInfo)-8, 0) == -1)
           {
               printf("msg send failed\n");
           }
           else
           {
               #ifdef DEBUG_PACKET
               printf("LAN: msg send success\n");
               #endif
           }

			/* check for originating traffic */
			if (tcph->syn)
			{
			    /* check if the traffic is coming in or leaving the interface */
			    // for now just use Outgoing and ignore incoming on the LAN side for Beta1
			    if (isOutgoing)
			    {
				#ifdef ENABLE_MUTEX
				sem_wait(&semDbInsertLock);
				#endif
	//		        printf("\n LAN:: TCP SYN pkt #:%d :%d\n", tcph->source, tcph->dest);
				// check the static IP list for both Black and White List. TODO
				create_query_string_tcp_lan(iph, tcph, WHITE_LIST, query);
				Count(con, query, &result);
				if(result == 0)
				{
				    #ifdef DEBUG_PRINT
				    printf("\nLAN::Inside WhiteList if condition: Query: %s , File: %s, Line: %d", query, __FILE__, __LINE__);
				    #endif
				   // if leaving, then the record should exist in State machine 
					create_query_string_tcp_lan(iph, tcph, STATE_LIST, query);
					Count(con, query, &result);
					#ifdef DEBUG_PRINT
					printf("\nLAN::State Machine if condtion. Query: %s, Count: %d\n", query, result);
					#endif
					if(result > 0)
					{
					    // check the black list before moving it in the white list
					   // if found then delete the record in Black list and then
					   // move the record into Whitelist
					    create_query_string_tcp_lan(iph, tcph, BLACK_LIST, query);
					     Count(con, query, &result);
					    if (result > 0)
					    {
						// Was in Black List earlier so delete from Black List here
						processAgain = !deleteTcpFromBlackList(con, iph, tcph);
					    }
					    if (isNat)
					    {
						// In NAT case, we have to extract the IPs from WAN (in DB) and replace it while inserting
						// into WhileList table.
						// Record exists in State machine. Move to WhiteList
					       // **** HM FIXME THES FUNCTIONS.. JUST END THE QUERY STRING NEXT ROUND
						processAgain = !moveTcpRecordToWhiteListFromStateMachineWithNat(con, iph, tcph, isPat);
					    }
					    else
					    {
						// NO NAT Case.
						// Record exists in State machine. Move to WhiteList
						// What ever is in the state table we should move to white list.
						processAgain = !moveTcpRecordToWhiteListFromStateMachineWithoutNat(con, iph, tcph);
					    }
					}
					else
					{
					    /* Error scenario as record should exist in State machine. Log for future debugging. */
			//		    printf ("\nLAN::ERROR** SLEEP protocol TCP src IP =%u, dst IP = %u, sport:%u, dport:%u\n", iph->saddr, iph->daddr, tcph->source, tcph->dest);
                                            processAgain = true;
                                        }
				    }
				    else
				    {
					#ifdef DEBUG_PRINT
					printf("\nLAN TCP:: Match Found WhiteList  Query: %s\n", query);
					#endif
				       //  delete from State Table since it is already in whitelist table
					if (isNat)
					 {
					      processAgain = !deleteTcpFromStateMachineWithNat(con, iph, tcph, isPat);
					 }
					 else
					 {
					      //processAgain = !deleteTcpFromStateMachineWithoutNat(con, iph, tcph);
	//				      printf("\nLAN TCP:: Match NOT found in State: processAgain-> %d\n", processAgain);
					 }

				    }
				  #ifdef ENABLE_MUTEX
				   sem_post(&semDbInsertLock);
				   #endif
				}
			 }
			else
			{
			    /* this is all traffic
			     */
			 //   printf ("\n LAN***All other traffic \n");
			}
			break;
		    case IPPROTO_UDP:
			udph = (struct udphdr *)(buffer+ sizeof(struct ethhdr)+iph->ihl*4);
 //printf ("\nLAN: UDP Algorithm details: Time-> %lf: SrcIP-> %u DstIP-> %u SrcPort-> %d DstPort-> %d  CNT-> %d\n", GetPrintTimeStamp(), iph->saddr, iph->daddr, udph->source, udph->dest, counter);

			if (dns_pkt_check_udp_lan(udph))
			{
			    #ifdef DEBUG_PACKET
			    printf ("\nLAN::UDP DNS pkt  :%d :%d", ntohs(udph->source), ntohs(udph->dest));
			    #endif
                            bufferPoolLAN[counter].inUse = false;
                            counter++;
			    continue;
			}

			    /* check if the traffic is coming in or leaving the interface */
			    // for now just use Outgoing and ignore incoming on the LAN side for Beta1
			    if (isOutgoing)
			    {
				#ifdef ENABLE_MUTEX
				sem_wait(&semDbInsertLock);
				#endif
				create_query_string_udp_lan(iph,  udph, WHITE_LIST, query);
				Count(con, query, &result);
				 if (result==0)
				  {
                                     #ifdef DEBUG_PRINT
                                      printf("\nLAN UDP::Inside WhiteList if condition: Query: %s , File: %s, Line: %d", query, __FILE__, __LINE__);
                                      #endif
					create_query_string_udp_lan(iph,  udph, STATE_LIST, query);
					Count(con, query, &result);
					if(result > 0)
					{
					   create_query_string_udp_lan(iph,  udph, BLACK_LIST, query);
					   Count(con, query, &result);
					    if (result > 0)
					    {
						// Was in Black List earlier so delete from Bl ack List here
						processAgain = !deleteUdpFromBlackList(con, iph, udph);
					    }
			  //      	printf("\nLAN UDP:: Inserting into WhiteList table: %s", query);
					     if (isNat)
					     {
						// Record exists in State machine. Move to WhiteList
						// FIXME *** HM similar to TCP
						processAgain = !moveUdpRecordToWhiteListFromStateMachineWithNat(con, iph, udph, isPat);
					     }
					     else
					     {
						// Record exists in State machine. Move to WhiteList
						// What ever is in the state table we should move to white list.
						processAgain = !moveUdpRecordToWhiteListFromStateMachineWithoutNat(con, iph, udph);
					     }
					  }
					  else
					  {
				         // Erroro as record should exist in State machine. 
			//			printf ("\nLAN::ERROR** protocol UDP  src IP =%u, dst IP = %u, sport:%d, dport:%u \n",iph->saddr, iph->daddr, udph->source, udph->dest);
                                                processAgain = true;
					  }
				  }
				  else
				  {
					#ifdef DEBUG_PRINT
					printf("\nLAN UDP:: Match Found WhiteList  Query: %s\n", query);
					#endif
				      // delete the state table entry here since it is already there in White List
				      processAgain = !deleteUdpFromState(con, iph, udph);
			              //printf("\nLAN UDP:: Match NOT found in State: processAgain-> %d\n", processAgain);

				  }
					#ifdef ENABLE_MUTEX
					sem_post(&semDbInsertLock);
					#endif
			       }
			break;
		    default:
			break;
		}
           }
           if (!processAgain)
           {
               bufferPoolLAN[counter].inUse = false;
               bufferPoolLAN[counter].length = 0;
               memset(bufferPoolLAN[counter].buffer, 0, (ETH_FRAME_LEN+1));
           }
           processAgain = false;
          }
          counter++;
      }
        pthread_exit(0); /* exit */
}

void processTelemetry()
{
    printf("\n Telemetry Thread started");

    /*
     * Code for Exclusive CPU
     * Let process/thread bind itself by executing syscall
     * #include <sched.h>
     * int sched_setaffinity(pid_t pid, unsigned int len, unsigned long *mask);
     *
     */
    while (1)
    {
        PktInfo pktInfoData;
        if (msgrcv(msgQueueId, &pktInfoData, sizeof(PktInfo)-8, 0, 0) == -1)
            printf("error in msgrcv\n");
        else
        {
            #ifdef DEBUG_PRINT
            printf("msg rcv success\n");
            printf("\npktInfoData[cnt].srcIP = %u",(unsigned int)pktInfoData.srcIP);
            printf("\npktInfoData[cnt].dstIP = %u",(unsigned int)  pktInfoData.dstIP);
            printf("\npktInfoData[cnt].srcPort = %d",  pktInfoData.srcPort);
            printf("\npktInfoData[cnt].dstPort = %d",  pktInfoData.dstPort);
            printf("\npktInfoData[cnt].protocol = %d", pktInfoData.protocol);
            printf("\npktInfoData[cnt].pktLen = %d", pktInfoData.pktLen);
            printf("\npktInfoData[cnt].timeStamp = %ld", pktInfoData.timestamp);
            printf("\npktInfoData[cnt].direction = %d \n", pktInfoData.direction);
            #endif

            /* Check if a hash entry exists for this packet. If it does, update the counters else
             * we need to populate a new entry to the hash.
             */
            // Take a lock on the hash.
            if (pthread_rwlock_rdlock(&hashLock) != 0)
            {
               printf("can't acquire readlock\n");
               exit(-1);
            }

            HashKey hashKey;
            hashKey.srcIP = pktInfoData.srcIP;
            hashKey.srcPort  = pktInfoData.srcPort;

            MeasData *measRec = findMeasRecord(&hashKey);

            if (measRec != NULL)
            {
                updateCounters(&pktInfoData, measRec);
            }
            else
            {
                addMeasRecord(&pktInfoData);
            }
            pthread_rwlock_unlock(&hashLock);
        }
        //printHashElements();

    }

    if (msgctl(msgQueueId, IPC_RMID, NULL) == -1) {
            perror("msgctl");
            exit(1);
     }

    pthread_exit(0); /* exit */
}

void processMonitor()
{
    printf("\nMonitor Thread started\n");
    MYSQL *con = NULL;

    // Connect to DB with initial soak time of 5ms.
    usleep(5000);
    con = Connect();
    while (1)
    {
        usleep(4000); // 4 milli second.
        #ifdef ENABLE_MUTEX
        sem_wait(&semDbInsertLock);
        #endif
        // Check for record older than 3 milli seconds in State machine
        processTimeoutInStateMachine(con);
        #ifdef ENABLE_MUTEX
        sem_post(&semDbInsertLock);
        #endif
    }
    // Disconnect DB.
    Disconnect(con);
    // Close processing
    pthread_exit(0); /* exit */
}

int main(int argc, char * argv[])
{
    pthread_t threadLan, threadWan, threadWanBuffer, threadLanBuffer,  threadTelemetry, threadMonitor, threadGenerateCsvData;  /* thread variables */
    int cnt=0;
    int temp, i;
    char *mac_value;


    for( cnt = 1; cnt < argc; cnt++ )
    {
        if (!(strcasecmp(argv[ cnt ], "VERSION")))
        {
            printf("\n########################################################");
            printf("\nDelta Engine version: 1.1\nRelease Date: Oct 24, 2013");
            printf("\n########################################################\n\n");
            //exit(0);
        }
        if (!(strcasecmp(argv[ cnt ], "NAT")))
        {
            isNat = true;
            printf("\nNAT check enabled");
        }
        if (!(strcasecmp(argv[ cnt ], "PAT")))
        {
            isPat = true;
            printf("\nPAT check enabled");
        }
    }

    #ifdef ENABLE_MUTEX
    /* Initialize semaphore for DB synchronization */
    sem_init(&semDbInsertLock, 0, 1);
    #endif

    // Create the unix sys 5 message queue
    key_t key;
    key = 12345;
    if ((msgQueueId = msgget(key, 0777 | IPC_CREAT)) == -1)
    {
        printf("Message Queue Creation failed\n");
        exit(1);
    }
    else
    {
        printf("Message Queue ID: %i\n", msgQueueId);
    }

   // create connection to the database for LAN and WAN side
      conlan = Connect();
      usleep(100);
      conwan = Connect();

   // read mac address from WAN and LAN side 
     mac_value = readPiMacOptions(conwan, "WAN_MAC_ADDRESS");
    if (mac_value== NULL)
    {
        printf ("Error in Pi Options table\n");
        Disconnect(conwan);
        pthread_exit(0);
    }

    for (i=0;i<6;i++)
    {
       sscanf(mac_value, "%2x", &temp);
       ethwan[i] = temp;
        mac_value +=2;
    }
     printf ("\nWAN::ETH MAC %x %x %x %x %x %x", ethwan[0], ethwan[1], ethwan[2], ethwan[3], ethwan[4], ethwan[5]);

     mac_value = readPiMacOptions(conlan, "LAN_MAC_ADDRESS");
    if (mac_value== NULL)
    {
        printf ("Error in Pi Options table\n");
        Disconnect(conlan);
        pthread_exit(0);
    }

    for (i=0;i<6;i++)
    {
       sscanf(mac_value, "%2x", &temp);
       ethlan[i] = temp;
        mac_value +=2;
    }
     printf ("\nLAN::ETH MAC %x %x %x %x %x %x", ethlan[0], ethlan[1], ethlan[2], ethlan[3], ethlan[4], ethlan[5]);

    /* create threads 1 and 2 */
    pthread_create (&threadLanBuffer, NULL, (void *) &processLanBufferTraffic, NULL);
    pthread_create (&threadLan, NULL, (void *) &processLanTraffic, NULL);
    pthread_create (&threadWan, NULL, (void *) &processWanTraffic, NULL);
    pthread_create (&threadWanBuffer, NULL, (void *) &processWanBufferTraffic, NULL);
    pthread_create (&threadTelemetry, NULL, (void *) &processTelemetry, NULL);
    pthread_create (&threadMonitor, NULL, (void *) &processMonitor, NULL);
    pthread_create (&threadGenerateCsvData, NULL, (void *) &generateCsvData, NULL);

    /* Main block now waits for both threads to terminate, before it exits.
       If main block exits, both threads exit, even if the threads have not
       finished their work. How about taking care of the case when one of the threads
       exists and has to re-start.. Need to take care of that.
     */
    pthread_join(threadWanBuffer, NULL);
    pthread_join(threadLanBuffer, NULL);
    pthread_join(threadTelemetry, NULL);
    pthread_join(threadGenerateCsvData, NULL);
    pthread_join(threadMonitor, NULL);
    pthread_join(threadWan, NULL);
    pthread_join(threadLan, NULL);

    printf ("\n ** after JOIN***\n");

    #ifdef ENABLE_MUTEX
    // Destroy semaphore.
    sem_destroy(&semDbInsertLock);
 //   sem_destroy(&semLanDoneLock);
    #endif

     msgctl(msgQueueId, IPC_RMID, NULL);
     Disconnect(conlan);
     Disconnect(conwan);
    /* exit */
    exit(0);
} 
