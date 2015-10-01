//
//  route.h
//  router
//
//  Created by Peera Yoodee on 9/28/15.
//

#ifndef __router__route__
#define __router__route__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "interface.h"

//struct routing {
//    uint32_t destination;
//    uint32_t netmask;
//    uint32_t gateway;
//    u_char gateway_macaddress[6];
//    char   interface[16];
//    short  interface_index;
//    u_char interface_macaddress[6];
//};

struct route {
    uint32_t destination;
    uint32_t netmask;
    uint32_t gateway;
    u_char gateway_macaddress[6];
    struct interface interface;
//    int sockfd;
};

void fprintf_route(FILE *out, struct route *r);

#endif /* defined(__router__routing__) */
