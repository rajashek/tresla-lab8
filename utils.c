//
//  utils.c
//  router
//
//  Created by Peera Yoodee on 9/24/15.
//

#include "utils.h"

uint32_t parse_ipv4_string(char *ip_address) {
    int ipbyte[4];
    sscanf(ip_address, "%d.%d.%d.%d", &ipbyte[0], &ipbyte[1], &ipbyte[2], &ipbyte[3]);
    return (ipbyte[0] & 0xff) | ((ipbyte[1] & 0xff) << 8) | ((ipbyte[2] & 0xff) << 16) | ((ipbyte[3] & 0xff) <<24);
}

char* ip_to_string(uint32_t ip) {
    char *p;
    p = malloc(sizeof(char) * 16);
    sprintf(p, "%d.%d.%d.%d", ip & 0xff, (ip >> 8) & 0xff, (ip >> 16) & 0xff, (ip >> 24) & 0xff);
    return p;
}
