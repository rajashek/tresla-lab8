//
//  main.c
//  router
//
//  Created by Peera Yoodee on 9/23/15.
//

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "interface.h"
#include "config.h"
#include "route.h"
#include "arp.h"
#include "sniffer.h"

#define _VERBOSE

void print_usage();

int main(int argc, const char * argv[]) {
    
    int i, j, k;
    FILE *file;
    char *arg_interface;
    char *token, *dup;
    
    int num_input_interfaces = 0;
    struct interface *input_interface;
    int num_routes = 0;
    struct route *routes;
    
    struct arp_linkedlist arp_table_root;
    
    int *num_installed_routes;
    struct route **installed_routes;
    
    if (argc <= 4) {
        print_usage();
        exit(1);
    }
    
    // Read command line arguments
    if (strcmp("-i", argv[1]) == 0) {
        arg_interface = strdup(argv[2]);
    }
    else {
        print_usage();
        exit(1);
    }
    
    if (strcmp("-f", argv[3]) == 0) {
        file = fopen(argv[4], "r");
        if(!file) {
            fprintf(stderr, "Error: cannot read the file %s\n", argv[2]);
            exit(1);
        }
    }
    else {
        print_usage();
        exit(1);
    }
    
    /*
     * CPU Prioritization
     *
     */
    
    // Increase the priority of the process (max priority is -20, min is 19)
    if (setpriority(PRIO_PROCESS, 0, -20) < 0) {
        fprintf(stderr, "** It is recommend to run as a superuser! **\n");
    }
    
    
    /*
     * Listening Interfaces - defined in command line arguments
     *
     */
    
    // Realloc doesn't work so we count commas to approx the number of interfaces
    for (i=0; i<strlen(arg_interface); i++) {
        if (arg_interface[i] == ',') num_input_interfaces++;
    }
    num_input_interfaces++;
    
    // Allocate input interface array
    input_interface = (struct interface *) malloc(num_input_interfaces * sizeof(struct interface));
    
    // Parse input interfaces
    num_input_interfaces = 0;
    dup = strdup(arg_interface);
    while ((token = strtok(dup, ",")) != NULL) {
        
        strcpy(input_interface[num_input_interfaces].interface_name, token);
        fill_interface_info(&input_interface[num_input_interfaces]);
        
        // Interface name is valid
        if (input_interface[num_input_interfaces].interface_index != -1) {
            num_input_interfaces++;
        }
        
        dup = NULL;
        
    }
    
    free(arg_interface);
    
    // Print listening interfaces information
    #ifdef _VERBOSE
    fprintf(stderr, "[LISTENING INTERFACES]\n");
    fprintf(stderr, "   Number of listening interfaces: %d\n", num_input_interfaces);
    fprintf(stderr, "   %-5s %-6s %-19s %-15s\n", "Dev", "DevId", "Interface MAC addr", "Inf IP addr");
    for(i=0; i<num_input_interfaces; i++) {
        fprintf(stderr, "%2d ", i+1);
        fprintf_interface(stderr, &input_interface[i]);
    }
    fprintf(stderr, "\n");
    #endif
    
    
    /*
     * ARP table
     *
     */
    
    // Initialize ARP table
    init_arp_table(&arp_table_root);
    
    
    /*
     * Routing table - constructing from the config file
     *
     */
    
    // Read config file and start everyting
    read_config(file, &routes, &num_routes);
    
    // Fill the interface info
    for(i=0; i<num_routes; i++) {
        fill_interface_info(&routes[i].interface);
        
        // Get gateway MAC address
        if (routes[i].gateway != 0) {
            if (get_mac_address(&arp_table_root, routes[i].gateway, &routes[i].interface) != NULL) {
                // Note: recalling get_mac_address to get MAC addr from arp table as I don't want to delare a variable :)
                memcpy(routes[i].gateway_macaddress, get_mac_address(&arp_table_root, routes[i].gateway, &routes[i].interface), ETHER_ADDR_LEN);
            }
            else {
                fprintf(stderr, "Error: Cannot find MAC address of Gateway %s\n\n", ip_to_string(routes[i].gateway));
            }
        }
        
    }
    
    // Print Routing Table
    #ifdef _VERBOSE
    fprintf(stderr, "[ROUTES]\n");
    fprintf(stderr, "   Number of defined routes: %d\n", num_routes);
    fprintf(stderr, "   %-15s %-15s %-15s %-18s %-5s %-6s %-19s %-15s\n",
            "Destination", "Netmask", "Gateway", "Gateway MAC addr", "Dev", "DevId", "Interface MAC addr", "Inf IP addr"
    );
    for(i=0; i<num_routes; i++) {

        fprintf(stderr, "%2d ", i+1);
        fprintf_route(stderr, &routes[i]);

    }
    fprintf(stderr, "\n");
    #endif
    
    
    /*
     * Prepare routes to install in each packet sniffing threads
     *
     */
    
    installed_routes = (struct route **) malloc(num_input_interfaces * sizeof(struct route *));
    num_installed_routes = (int *) malloc(num_input_interfaces * sizeof(int));
    
    for(i=0; i<num_input_interfaces; i++) {
        // Count the number of routes each interface needs
        num_installed_routes[i] = 0;
        for(j=0; j<num_routes; j++) {
            if (input_interface[i].interface_index != routes[j].interface.interface_index) {
                num_installed_routes[i]++;
            }
        }
        
        // Copy those routes to dedicated array of routes
        installed_routes[i] = (struct route *) malloc(num_installed_routes[i] * sizeof(struct route));
        for(j=0, k=0; j<num_routes; j++) {
            if (input_interface[i].interface_index != routes[j].interface.interface_index) {
                memcpy(&installed_routes[i][k], &routes[j], sizeof(struct route));
                k++;
            }
        }
        
    }
    
    // Prints
    #ifdef _VERBOSE
    fprintf(stderr, "[PACKET SNIFFING THREADS]\n");
    for(i=0; i<num_input_interfaces; i++) {
        
        fprintf(stderr, "%2d Device: %s \n", i+1, input_interface[i].interface_name);
        
        for(j=0; j<num_installed_routes[i]; j++) {
            fprintf(stderr, "%-4s%2d.%-2d ", "", i+1, j+1);
            fprintf_route(stderr, &installed_routes[i][j]);
        }
        
    }
    fprintf(stderr, "\n");
    #endif
    

    /*
     * Start packet sniffing threads
     *
     */
    
    pthread_t thread[num_input_interfaces];
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    
    struct sniffer_thread_parameter params[num_input_interfaces];
    
    for (i=0; i<num_input_interfaces; i++) {
        fprintf(stderr, "[Start sniffer #%d]\n", i+1);
        
        
        params[i].sniff_interface = &input_interface[i];
        params[i].num_routes = &num_installed_routes[i];
        params[i].routes = &installed_routes[i];
        params[i].arp_table_root = &arp_table_root;
        
        if (pthread_create(&thread[i], &attr, sniffer_thread, (void *) &params[i]) < 0) {
            fprintf(stderr, "Error: Can not create a thread for the sniffer_thread in main()\n");
        }
        
    }

    for (i=0; i<num_input_interfaces; i++) {
        pthread_join(thread[i], NULL);
    }
    
    return 0;
    
}

void print_usage() {
    fprintf(stderr, "Error: invalid options\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  fscp -i eth0,eth1 -f routing.conf\n");
}