//
//  sniffer.h
//  router
//
//  Created by Peera Yoodee on 9/30/15.
//

#ifndef __router__sniffer__
#define __router__sniffer__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <pcap.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/route.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/ip_icmp.h>

#include <pthread.h>

#include "interface.h"
#include "route.h"
#include "arp.h"
#include "utils.h"

#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define SIZE_ICMP 8

#define _VERBOSE

struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

struct sniff_ip {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
    #define IP_RF 0x8000            /* reserved fragment flag */
    #define IP_DF 0x4000            /* dont fragment flag */
    #define IP_MF 0x2000            /* more fragments flag */
    #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

struct icmpheader
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t rest;
};

struct sniffer_thread_parameter {
    struct interface *sniff_interface;
    int *num_routes;
    struct route **routes;
    struct arp_linkedlist *arp_table_root;
};

struct got_packet_parameter {
    struct interface *sniff_interface;
    int *num_routes;
    struct route **routes;
    struct arp_linkedlist *arp_table_root;
};

void *sniffer_thread(void *params);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
short num_prefix_match(uint32_t ip_destination, uint32_t route_destination, uint32_t route_netmask);
u_short ip_checksum(u_short *ptr, int nbytes);

#endif /* defined(__router__sniffer__) */
