#ifndef __DISASM_TOOL_H__
#define __DISASM_TOOL_H__

#include <sys/ptrace.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <capstone/capstone.h>

#include "types.h"

#define PEEKSIZE 8

void disassembler_open(csh *handle);
void disassembler_close(csh *handle);

void disassemble_at_break(tracee_t *tracee, csh handle, int hit_id);
unsigned long long disassemble(csh handle, unsigned char *code, unsigned long long code_size, unsigned long long addr, int disasm_size);
unsigned long long disassemble_in_running(tracee_t *tracee, csh handle, unsigned long long addr);
void print_instruction(cs_insn *insn);

#endif
