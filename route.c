//
//  route.c
//  router
//
//  Created by Peera Yoodee on 9/28/15.
//

#include "route.h"

void fprintf_route(FILE *out, struct route *route) {
    fprintf(out, "%-15s %-15s %-15s %.2x:%.2x:%.2x:%.2x:%.2x:%.2x  %-5s %-6d %.2x:%.2x:%.2x:%.2x:%.2x:%.2x   %-15s\n",
        ip_to_string(route->destination),
        ip_to_string(route->netmask),
        ip_to_string(route->gateway),
        PRINT_MAC(route->gateway_macaddress),
        route->interface.interface_name,
        route->interface.interface_index,
        PRINT_MAC(route->interface.interface_macaddress),
        ip_to_string(route->interface.interface_ipaddress)
    );
}
