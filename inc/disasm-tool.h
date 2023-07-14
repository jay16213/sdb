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
#include "util.h"

typedef struct disassembler_t disassembler_t;

disassembler_t* disasm_init();
void disasm_finalize(disassembler_t* disassembler);

void disasm_at_break(disassembler_t* disassembler, int hit_id);
uint64_t disasm(disassembler_t* disassembler, uint8_t *code, uint64_t code_size, uint64_t addr, int disasm_size);
uint64_t disasm_in_running(disassembler_t* disassembler, uint64_t addr);

#endif
