//
//  arp.h
//  router
//
//  Created by Peera Yoodee on 9/29/15.
//

#ifndef __router__arp__
#define __router__arp__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <net/ethernet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <asm/types.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>

#include "utils.h"
#include "interface.h"

#define BUF_SIZE 42     // Ethernet(14) + ARP(28)
#define SIZE_ETHERNET 14
#define ETHER_TYPE_FOR_ARP 0x0806

#define HW_TYPE_FOR_ETHER 0x0001
#define HW_LEN_FOR_ETHER 0x06
#define HW_LEN_FOR_IP 0x04
#define PROTO_TYPE_FOR_IP 0x0800
#define OP_CODE_FOR_ARP_REQ 0x0001

#define ARP_TIMEOUT 1   // Timeout in second

//#define _VERBOSE

struct ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

struct __attribute__((packed)) arp_packet
{
    unsigned short arp_hd;
    unsigned short arp_pr;
    unsigned char arp_hdl;
    unsigned char arp_prl;
    unsigned short arp_op;
    unsigned char arp_sha[6];
    unsigned long arp_spa;
    unsigned char arp_dha[6];
    unsigned long arp_dpa;
};

struct arp_record {
    uint32_t ip_address;
    u_char   mac_address[ETHER_ADDR_LEN];
};

struct arp_linkedlist {
    struct arp_record node;
    struct arp_linkedlist *next;
};

void init_arp_table(struct arp_linkedlist *root);
u_char *get_mac_address(struct arp_linkedlist *root, uint32_t ip_address, struct interface *interface);
u_char *get_mac_from_arp(uint32_t ip_address, struct interface *interface);

#endif /* defined(__router__arp__) */
