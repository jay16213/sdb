#ifndef __TYPES_H__
#define __TYPES_H__

#include "elftool.h"

#define BYTE_MASK 0xffffffffffffff00

typedef struct range_s
{
    uint64_t begin;
    uint64_t end;
} range_t;

typedef struct map_entry_s
{
    range_t range;
    int perm;
    long offset;
    char *name;
    struct map_entry_s *next;
} map_entry_t;

#endif
