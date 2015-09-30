//
//  interface.c
//  router
//
//  Created by Peera Yoodee on 9/24/15.
//

#include "interface.h"

/*void print_interfaces() {
    
    struct ifaddrs *ifap, *ifa;
    
    char *ifname;
    ifname = (char *) malloc(sizeof(char) * 16);
    
    uint32_t ipaddress, netmask, netaddress, ifindex = 0;
    u_char hwaddr[6];
    
    struct ifreq ifr;

    int sd = socket(PF_INET, SOCK_DGRAM, 0);
    
    getifaddrs (&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family==AF_INET) {
            ipaddress = (((struct sockaddr_in *) ifa->ifa_addr)->sin_addr).s_addr;
            netmask = (((struct sockaddr_in *) ifa->ifa_netmask)->sin_addr).s_addr;
            netaddress = ipaddress & netmask;
            strcpy(ifname, ifa->ifa_name);
            strcpy(ifr.ifr_name, ifa->ifa_name);
            // Get Interface Index
            if (ioctl(sd, SIOCGIFINDEX, &ifr) == 0) {
                ifindex = ifr.ifr_ifindex;
            }
            // Get Interface MAC address
            if (ioctl(sd, SIOCGIFHWADDR, &ifr) == 0) {
                memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, 6);
            }
            printf("%2d %-7s %.8x %.8x %.8x %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", ifindex, ifname, ipaddress, netmask, netaddress, PRINT_MAC(hwaddr));
        }
    }
    
    freeifaddrs(ifap);
    close(sd);
    
}*/

void fill_interface_info(struct interface *inf) {

    struct ifreq ifr;
    strcpy(ifr.ifr_name, inf->interface_name);
    
    int sd = socket(PF_INET, SOCK_DGRAM, 0);
    
    // Get Interface Index
    if (ioctl(sd, SIOCGIFINDEX, &ifr) == 0) {
        inf->interface_index = ifr.ifr_ifindex;
    }
    else {
        inf->interface_index = -1;
    }
    
    // Get Interface MAC address
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) == 0) {
        memcpy(inf->interface_macaddress, ifr.ifr_hwaddr.sa_data, 6);
    }
    else {
        memset(inf->interface_macaddress, 0, 6);
    }
    
    // Get IP address
    if (ioctl(sd, SIOCGIFADDR, &ifr) == 0) {
        inf->interface_ipaddress = ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr;
    }
    else {
        inf->interface_ipaddress = 0;
    }
    
    // Get Netmask
    if (ioctl(sd, SIOCGIFNETMASK, &ifr) == 0) {
        inf->interface_netmask = ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr;
    }
    else {
        inf->interface_netmask = ~0;
    }
    
    // Set Network address
    inf->interface_netaddress = inf->interface_ipaddress & inf->interface_netmask;
    
    close(sd);
    
}

void fprintf_interface(FILE *out, struct interface *intf) {
    fprintf(out, "%-5s %-6d %.2x:%.2x:%.2x:%.2x:%.2x:%.2x   %-15s\n",
        intf->interface_name,
        intf->interface_index,
        PRINT_MAC(intf->interface_macaddress),
        ip_to_string(intf->interface_ipaddress)
    );
}

