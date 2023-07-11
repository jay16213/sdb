#ifndef __TYPES_H__
#define __TYPES_H__

#include "elftool.h"

#define MAX_BREAKPOINTS 1024
#define BYTE_MASK 0xffffffffffffff00

typedef struct range_s
{
    unsigned long long begin, end;
} range_t;

typedef struct map_entry_s
{
    range_t range;
    int perm;
    long offset;
    char *name;
    struct map_entry_s *next;
} map_entry_t;

// id == -1 -> not used
typedef struct breakpoint
{
    int id;
    unsigned long long address;
    unsigned char origin_code;
} breakpoint_t;

typedef struct tracee_s
{
    int pid;
    char program_name[256];
    unsigned long long baseaddr;
    elf_shdr_t text_shdr;
    range_t text_section_addr;
    range_t text_phaddr; // real addr map when the program is running
    int elf_type;
    unsigned char *text;
    unsigned long long last_disasm_addr;
    unsigned long long last_dump_addr;
    breakpoint_t breakpoints[MAX_BREAKPOINTS];
} tracee_t;

#endif
