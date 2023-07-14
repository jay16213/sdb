#ifndef __UTIL_H__
#define __UTIL_H__

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>

#include <capstone/capstone.h>

#include "types.h"

#ifdef DEBUG
#include "debug.h"
#endif

#define DELIMETER " \r\n"

void error_quit(const char *msg);

int inside_range(unsigned long long target, range_t range);

// if reg_name == NULL -> print all values
void print_register_value(struct user_regs_struct *regs, char *reg_name);
int set_register_value(struct user_regs_struct *regs, char *reg_name, unsigned long long val);
void get_register_values(pid_t tracee, struct user_regs_struct *regs);

unsigned long long dump_code(pid_t tracee, unsigned long long addr);
void print_instruction(cs_insn *insn);

void help_msg();

#endif
