//
//  interface.h
//  router
//
//  Created by Peera Yoodee on 9/24/15.
//

#ifndef __router__interface__
#define __router__interface__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include "utils.h"

struct interface {
    char     interface_name[16];
    short    interface_index;
    u_char   interface_macaddress[6];
    uint32_t interface_ipaddress;
    uint32_t interface_netmask;
    uint32_t interface_netaddress;
    int      sockfd;
};

//void print_interfaces();
void fill_interface_info(struct interface *inf);
void fprintf_interface(FILE *out, struct interface *intf);

#endif /* defined(__router__interface__) */
