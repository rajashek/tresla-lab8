//
//  sniffer.c
//  router
//
//  Modified by Peera Yoodee on 9/30/15.
//  Original code from http://www.tcpdump.org/sniffex.c
//

#include "sniffer.h"

void *sniffer_thread(void *params) {
    
    struct sniffer_thread_parameter *p = (struct sniffer_thread_parameter *) params;
    struct interface *sniff_interface = p->sniff_interface;
    int *num_routes = p->num_routes;
    struct route **routes = p->routes;
    struct arp_linkedlist *arp_table_root = p->arp_table_root;
    
    char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
    pcap_t *handle;                     /* packet capture handle */
    
    char filter_exp[64];                /* filter expression [3] */
    sprintf(filter_exp, "ip and ether dst %.2x:%.2x:%.2x:%.2x:%.2x:%.2x and dst not %s", PRINT_MAC(sniff_interface->interface_macaddress), ip_to_string(sniff_interface->interface_ipaddress));
    
    struct bpf_program fp;              /* compiled filter program (expression) */
    
    struct got_packet_parameter got_packet_param;
    struct sockaddr_ll sa;
    
    int i;

    /* open capture device */
    handle = pcap_open_live(sniff_interface->interface_name, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", sniff_interface->interface_name, errbuf);
        exit(EXIT_FAILURE);
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", sniff_interface->interface_name);
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, sniff_interface->interface_netaddress) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    
    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // Open socket for all output interface
    for (i=0; i<*num_routes; i++) {
        
        sa.sll_family = PF_PACKET;
        sa.sll_ifindex = (*routes)[i].interface.interface_index;
        sa.sll_halen = ETHER_ADDR_LEN;
        sa.sll_protocol = htons(ETH_P_802_3);
        sa.sll_hatype = 0;
        sa.sll_pkttype = 0;
        memcpy(sa.sll_addr, (*routes)[i].interface.interface_macaddress, ETHER_ADDR_LEN);
        
        (*routes)[i].sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_802_3));
        if ((*routes)[i].sockfd == -1) {
            fprintf(stderr, "Cannot create raw socket in sniffer_thread\n");
            fprintf(stderr, "%s\n", strerror(errno));
        }
    
        if (bind((*routes)[i].sockfd, (struct sockaddr *)&sa, sizeof(sa)) != 0){  //WARNING
            fprintf(stderr, "Cannot bind to raw socket in sniffer_thread\n");
        }
        
    }
    
    
    
    // Parse information to got_packet handler
    got_packet_param.num_routes = num_routes;
    got_packet_param.routes = routes;
    got_packet_param.arp_table_root = arp_table_root;



    
//    struct arp_linkedlist *n;
//    n = arp_table_root;
//    
//    while (n!=NULL) {
//        fprintf(stderr, "%s\n", ip_to_string(n->node.ip_address));
//        n = n->next;
//    }

    pcap_loop(handle, -1, got_packet, (u_char *) &got_packet_param);
    
    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    fprintf(stderr, "\nCapture complete.\n");
    
    return 0;
}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    
    // declare pointers to packet headers
    struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    struct sniff_ip *ip;              /* The IP header */
    struct got_packet_parameter *got_packet_param;
    
    int *num_routes;
    struct route *routes;
    struct route *route_match;
    struct arp_linkedlist *arp_table_root;
    
    int i;
    int size_ip_header;
    int prefix_match, longest_prefix_match, longest_prefix_match_route;
    
    u_char *dst_macaddr;
    
    ssize_t len;
    
    // Note: header-> len is size of a whole ethernet frame
    
    // Reconstruct parameter
    got_packet_param = (struct got_packet_parameter *) args;
    num_routes = got_packet_param->num_routes;
    routes = *got_packet_param->routes;
    arp_table_root = got_packet_param->arp_table_root;
    
    // define ethernet header
    ethernet = (struct sniff_ethernet*) packet;
    
    // define/compute ip header offset
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    
    size_ip_header = IP_HL(ip)*4;
    if (size_ip_header < 20) {
        fprintf(stderr, "   * Invalid IP header length: %u bytes\n", size_ip_header);
        return;
    }
    
    
    #ifdef _VERBOSE
    fprintf(stderr, "%s > ", inet_ntoa(ip->ip_src));
    fprintf(stderr, "%s\n", inet_ntoa(ip->ip_dst));
    #endif
    

    // Find the route that gives the longest prefix match
    longest_prefix_match = 0;
    longest_prefix_match_route = 0;
    for(i=0; i<*(got_packet_param->num_routes); i++) {
        prefix_match = num_prefix_match(ip->ip_dst.s_addr, routes[i].destination, routes[i].netmask);
        if (prefix_match > longest_prefix_match) {
            longest_prefix_match = prefix_match;
            longest_prefix_match_route = i;
        }
    }
    route_match = &routes[longest_prefix_match_route];
    
    #ifdef _VERBOSE
    printf(" Route to: %s %s\n",
        ip_to_string(route_match->destination),
        ip_to_string(route_match->gateway)
    );
    #endif
    
    // Decrease TTL
    ip->ip_ttl = ip->ip_ttl-1;
    
    if (ip->ip_ttl == 0) {
        // Drop
        return;
    }
    
    ip->ip_sum = 0;
    ip->ip_sum = ip_checksum((u_short *) (packet + SIZE_ETHERNET), size_ip_header);
    
    memcpy(ethernet->ether_shost, route_match->interface.interface_macaddress, ETHER_ADDR_LEN);
    
    if (route_match->gateway == 0) {
        // The destination is in the network we connect to
        // Forward the packet to the destination (we need to know MAC addr of the destination)
        if ((dst_macaddr = get_mac_address(arp_table_root, ip->ip_dst.s_addr, &route_match->interface)) != NULL) {
            memcpy(ethernet->ether_dhost, dst_macaddr, ETHER_ADDR_LEN);
        }
        else {
            fprintf(stderr, "Error: Cannot find MAC address of destination IP %s\n\n", ip_to_string(ip->ip_dst.s_addr));
            return;
        }
        
    }
    else {
        // The destination is in the network we don't connect to
        // Forward to the next hop gateway
        
        if ((dst_macaddr = get_mac_address(arp_table_root, route_match->gateway, &route_match->interface)) != NULL) {
            memcpy(ethernet->ether_dhost, dst_macaddr, ETHER_ADDR_LEN);
        }
        else {
            fprintf(stderr, "Error: Cannot find MAC address of gateway IP %s\n\n", ip_to_string(route_match->gateway));
            return;
        }
        
    }
    
    // Forward modified packet via appropriate output interface
    if ((len = send(route_match->sockfd, packet, header->len, 0)) < 0) {
        fprintf(stderr, "Error: Cannot send packet via %s to %s\n\n", route_match->interface.interface_name, ip_to_string(ip->ip_dst.s_addr));
        return;
    }
    
    return;
}

short num_prefix_match(uint32_t ip_destination, uint32_t route_destination, uint32_t route_netmask) {
    short i;
    uint32_t prefix_match = ntohl(~(route_destination ^ ip_destination) & route_netmask);
    for(i=0; i<32; i++) {
        if ((0x80000000 & prefix_match) == 0) break;
        prefix_match <<= 1;
    }
    return i;
}

u_short ip_checksum(u_short *ptr, int nbytes) {
    // Create Checksum of IP header (Modified version)
    // original: http://www.binarytides.com/raw-udp-sockets-c-linux/
    //
    long sum;
    u_short oddbyte = 0;
    
    sum=0;
    while(nbytes>1) {
        sum+=ntohs(*ptr++);
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
    
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);

    return htons((u_short)~sum);
}