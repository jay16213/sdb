#ifndef __TRACEE_H__
#define __TRACEE_H__

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include "types.h"
#include "util.h"

#define MAX_BREAKPOINTS 1024

typedef struct breakpoint_t
{
    int id;
    uint64_t address;
    unsigned char origin_code;
} breakpoint_t;

typedef struct tracee_t
{
    int               pid;
    char              program_name[256];
    uint64_t          baseaddr;
    elf_shdr_t        text_shdr;
    range_t           text_section_addr;
    range_t           text_phaddr; // real addr map when the program is running
    int               elf_type;
    unsigned char     *text;
    uint64_t          last_disasm_addr;
    uint64_t          last_dump_addr;
    breakpoint_t      breakpoints[MAX_BREAKPOINTS];
} tracee_t;

void init_tracee(tracee_t *tracee);
void free_tracee(tracee_t *tracee);

int load_elf(tracee_t *tracee, char *program_name);
int create_tracee_process(tracee_t *tracee);
int is_tracee_exit(tracee_t *tracee, int wait_status);
void tracee_single_step(tracee_t *tracee, int *wait_status);

// functions releated to handling breakpoints
int hit_breakpoint(tracee_t *tracee, uint64_t address);
int set_breakpoint(tracee_t *tracee, uint64_t target_addr, uint64_t *code);
int restore_code(tracee_t *tracee, struct user_regs_struct *regs, int bpoint_id, int reset);
int find_breakpoint(tracee_t *tracee, int id);

void add_breakpoint_to_list(tracee_t *tracee, uint64_t address, uint64_t code);
void delete_breakpoint_from_list(tracee_t *tracee, int id);
void disable_all_breakpoints(tracee_t *tracee);
void enable_all_breakpoints(tracee_t *tracee);
void get_breakpoints_origin_code(tracee_t *tracee);

void print_breakpoint_list(tracee_t *tracee);

#endif
