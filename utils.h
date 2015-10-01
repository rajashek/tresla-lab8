//
//  utils.h
//  router
//
//  Created by Peera Yoodee on 9/24/15.
//

#ifndef __router__utils__
#define __router__utils__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

#define PRINT_MAC(_addr)  _addr[0]&0xFF, _addr[1]&0xFF, _addr[2]&0xFF, _addr[3]&0xFF, _addr[4]&0xFF, _addr[5]&0xFF

uint32_t parse_ipv4_string(char *ip_address);
char* ip_to_string(uint32_t ip);

#endif /* defined(__router__utils__) */
