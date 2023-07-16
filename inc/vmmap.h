#ifndef __VMMAP_H__
#define __VMMAP_H__

#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "types.h"
#include "tracee.h"

int load_maps(tracee_t *tracee, int print_result);

#endif
