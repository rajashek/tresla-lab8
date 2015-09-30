//
//  arp.c
//  router
//
//  Created by Peera Yoodee on 9/29/15.
//

#include "arp.h"

void init_arp_table(struct arp_linkedlist *root) {

    root->node.ip_address = 0;
    memset(root->node.mac_address, 0x00, ETHER_ADDR_LEN);
    root->next = NULL;
    
}

u_char *get_mac_address(struct arp_linkedlist *root, uint32_t ip_address, struct interface *interface) {
    
    struct arp_linkedlist *current = NULL;
    struct arp_linkedlist *previous = NULL;
    
    u_char *mac_address;
    
    current = root;
    
    // Lookup the MAC address in the arp table
    while (current!=NULL) {
        #ifdef _VERBOSE
        fprintf(stderr, "<get_mac_address()> Node IP: %s\n", ip_to_string(current->node.ip_address));
        #endif
        
        if (current->node.ip_address == ip_address) {
            mac_address = (u_char *) malloc (ETHER_ADDR_LEN);
            memcpy(mac_address, current->node.mac_address, ETHER_ADDR_LEN);
            
            #ifdef _VERBOSE
            fprintf(stderr, "<get_mac_address()> Found MAC address: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", PRINT_MAC(mac_address));
            #endif
            
            return mac_address;
        }
        
        previous = current;
        current = current->next;
        
    }
    
    // Arp table doesn't have it, then begin the arp process
    #ifdef _VERBOSE
    fprintf(stderr, "<get_mac_address()> We don't have the MAC address of %s. Send ARP packet via %s.\n", ip_to_string(ip_address), interface->interface_name);
    #endif
    
    mac_address = get_mac_from_arp(ip_address, interface);
    if (mac_address != NULL) {
        
        current = (struct arp_linkedlist *) malloc(sizeof(struct arp_linkedlist));
        current->node.ip_address = ip_address;
        memcpy(current->node.mac_address, mac_address, ETHER_ADDR_LEN);
        current->next = NULL;
        
        if (previous != NULL) {
            previous->next = current;
        }
        
    }
    
    #ifdef _VERBOSE
    if (mac_address != NULL) {
        fprintf(stderr, "<get_mac_address()> %s replies %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", ip_to_string(ip_address), PRINT_MAC(mac_address));
    }
    else {
        fprintf(stderr, "<get_mac_address()> Nobody responds\n");
    }
    #endif
    
    return mac_address;
    
}

u_char *get_mac_from_arp(uint32_t ip_address, struct interface *interface) {
 
    int arp_fd;
    ssize_t len;
    
    struct timeval timeout;
    timeout.tv_sec = ARP_TIMEOUT;
    timeout.tv_usec = 0;
    
    u_char *mac_address;
    
    u_char *arp_buffer;
    arp_buffer = (u_char *) malloc(BUF_SIZE);
    
    struct ethernet *eth_header;
    eth_header = (struct ethernet*) arp_buffer;
    
    struct arp_packet *arp_packet;
    arp_packet = (struct arp_packet *)(arp_buffer + SIZE_ETHERNET);
    
    arp_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if(arp_fd == -1) {
        perror("ARP Socket");
        exit(1);
    }
    
    // Set receive timeout
    setsockopt (arp_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

    // Ethernet header
    memset(eth_header->ether_dhost, 0xFF, ETHER_ADDR_LEN);
    memcpy(eth_header->ether_shost, interface->interface_macaddress, ETHER_ADDR_LEN);
    eth_header->ether_type = htons(ETHER_TYPE_FOR_ARP);
    
    // ARP header
    arp_packet->arp_hd = htons(HW_TYPE_FOR_ETHER);
    arp_packet->arp_pr = htons(PROTO_TYPE_FOR_IP);
    arp_packet->arp_hdl = HW_LEN_FOR_ETHER;
    arp_packet->arp_prl = HW_LEN_FOR_IP;
    arp_packet->arp_op = htons(OP_CODE_FOR_ARP_REQ);
    memcpy(arp_packet->arp_sha, interface->interface_macaddress, ETHER_ADDR_LEN);
    arp_packet->arp_spa = interface->interface_ipaddress;
    memset(arp_packet->arp_dha, 0, ETHER_ADDR_LEN);
    arp_packet->arp_dpa = ip_address;
    
    struct sockaddr_ll sa;
    sa.sll_family = PF_PACKET;
    sa.sll_ifindex = interface->interface_index;
    sa.sll_halen = ETHER_ADDR_LEN;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_hatype = 0;
    sa.sll_pkttype = 0;
    memcpy(sa.sll_addr, interface->interface_macaddress, ETHER_ADDR_LEN);
    
    len = sendto(arp_fd, arp_buffer, BUF_SIZE, 0,(struct sockaddr *)&sa, sizeof(sa));
    if (len<0) {
        fprintf(stderr, "Error sending an ARP packet.");
        close(arp_fd);
        return NULL;
    }
    
    len = recvfrom(arp_fd, arp_buffer, BUF_SIZE, 0, NULL, NULL);
    if (len <0) {
        //fprintf(stderr, "Error receiving an ARP packet.");
        close(arp_fd);
        return NULL;
    }
    
    mac_address = (u_char *) malloc(ETHER_ADDR_LEN);
    memcpy(mac_address, arp_packet->arp_sha, ETHER_ADDR_LEN);
    close(arp_fd);
    
    return mac_address;
    
}
