//
//  config.c
//  router
//
//  Created by Peera Yoodee on 9/28/15.
//

#include "config.h"

void read_config(FILE *file, struct route **routes, int *num_routes) {
    
    struct route *r;
    
    char *line = NULL;
    char *token, *dup;
    size_t len = 0;
    ssize_t read;
    
    *num_routes = 0;
    
    // We need to count how many routes are defined since realloc() doesn't work with unknown causes
    while ((read = getline(&line, &len, file)) != -1) {
        dup = strdup(line);

        token = strtok(dup, " \t");
        if(token == NULL) { continue; }
            
        // Skip comment lines
        if(token[0] == '#') {
            continue;
        }
        
        *num_routes = *num_routes + 1;
        
    }
    
    fseek(file, 0, SEEK_SET);

    *routes = (struct route *) malloc(*num_routes * sizeof(struct route));
    r = *routes;
    
    while ((read = getline(&line, &len, file)) != -1) {
        dup = strdup(line);
        
        token = strtok(dup, " \t");
        if(token == NULL) { continue; }
        
        // Skip comment lines
        if(token[0] == '#') {
            continue;
        }
        
        // Get Destination Network
        r->destination = parse_ipv4_string(token);
        
        token = strtok(NULL, " \t");
        if(token == NULL) { continue; }
        
        // Get Netmask
        r->netmask = parse_ipv4_string(token);
        
        token = strtok(NULL, " \t");
        if(token == NULL) { continue; }
        
        // Get Gateway IP address
        r->gateway = parse_ipv4_string(token);
        
        token = strtok(NULL, " \t\n");
        if(token == NULL) { continue; }
        
        // Get Interface name
        strcpy(r->interface.interface_name, token);

        r++;
    }
    
    fclose(file);
    
}