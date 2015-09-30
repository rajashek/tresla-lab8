//
//  config.h
//  router
//
//  Created by Peera Yoodee on 9/28/15.
//

#ifndef __router__config__
#define __router__config__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "route.h"
#include "interface.h"
#include "utils.h"

void read_config(FILE *file, struct route **routes, int *num_routes);

#endif /* defined(__router__config__) */
