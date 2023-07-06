#ifndef __TRACEE_H__
#define __TRACEE_H_

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include "types.h"
#include "util.h"

void init_tracee(tracee_t *tracee);
void free_tracee(tracee_t *tracee);

int load_elf(tracee_t *tracee, char *program_name);
int create_tracee_process(tracee_t *tracee);
int is_tracee_exit(tracee_t *tracee, int wait_status);
void tracee_single_step(tracee_t *tracee, int *wait_status);

// functions releated to handling breakpoints
int hit_breakpoint(tracee_t *tracee, unsigned long long address);
int set_breakpoint(tracee_t *tracee, unsigned long long target_addr, unsigned long long *code);
int restore_code(tracee_t *tracee, struct user_regs_struct *regs, int bpoint_id, int reset);
int find_breakpoint(tracee_t *tracee, int id);

void add_breakpoint_to_list(tracee_t *tracee, unsigned long long address, unsigned long long code);
void delete_breakpoint_from_list(tracee_t *tracee, int id);
void disable_all_breakpoints(tracee_t *tracee);
void enable_all_breakpoints(tracee_t *tracee);
void get_breakpoints_origin_code(tracee_t *tracee);

void print_breakpoint_list(tracee_t *tracee);

#endif
