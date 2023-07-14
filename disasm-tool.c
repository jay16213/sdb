#include "inc/disasm-tool.h"

#define PEEKSIZE 8

struct disassembler_t {
    csh      handle;  // capstone handle
    tracee_t *tracee;
};

disassembler_t* disasm_init(tracee_t *tracee)
{
    disassembler_t *disassembler = (disassembler_t*) malloc(sizeof(disassembler_t));

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &disassembler->handle) != CS_ERR_OK)
        cs_errno(disassembler->handle);

    disassembler->tracee = tracee;

    return disassembler;
}

void disasm_finalize(disassembler_t* disassembler)
{
    cs_close(&disassembler->handle);
    free(disassembler);
}

void disasm_at_break(disassembler_t* disassembler, int hit_id)
{
    tracee_t *tracee = disassembler->tracee;
    breakpoint_t *bp = tracee->breakpoints;
    int count;
    uint64_t has_read = 0;
    uint64_t code = 0;
    uint64_t addr = bp[hit_id].address + tracee->baseaddr;
    unsigned char *cptr = (unsigned char *)&code;
    cs_insn *insn;

    // get current code
    if ((code = ptrace(PTRACE_PEEKTEXT, tracee->pid, addr, 0)) < 0)
    {
        perror("get current code error");
        return;
    }

    code = (code & BYTE_MASK) | bp[hit_id].origin_code;

    if ((count = cs_disasm(disassembler->handle, cptr, sizeof(uint64_t), addr, 1, &insn)) > 0)
    {
        int i;
        for (i = 0; i < count; i++)
        {
            has_read += insn[i].size;
            print_instruction(&insn[i]);
        }

        cs_free(insn, count);
    }
    else
        fprintf(stderr, "disasm error\n");

    return;
}

uint64_t disasm(disassembler_t* disassembler, uint8_t *code, uint64_t code_size, uint64_t addr, int disasm_size)
{
    int count;
    uint64_t has_read = 0;
    cs_insn *insn;

    if ((count = cs_disasm(disassembler->handle, code, code_size, addr, disasm_size, &insn)) > 0)
    {
        int i;
        for (i = 0; i < count; i++)
        {
            has_read += insn[i].size;
            print_instruction(&insn[i]);
        }

        cs_free(insn, count);
    }
    else
    {
        fprintf(stderr, "disasm error\n");
    }

    return addr + has_read;
}

uint64_t disasm_in_running(disassembler_t* disassembler, uint64_t addr)
{
    int count;
    uint64_t has_read = 0;
    char buf[80] = {0};
    // uint64_t addr = baseaddr + offset;
    uint64_t ptr = addr;
    cs_insn *insn;

    for (ptr = addr; ptr < addr + sizeof(buf); ptr += PEEKSIZE)
    {
        long long peek;
        errno = 0;
        peek = ptrace(PTRACE_PEEKTEXT, disassembler->tracee->pid, ptr, NULL);
        if (errno != 0)
            break;
        memcpy(&buf[ptr - addr], &peek, PEEKSIZE);
    }

    if (ptr == addr)
        return addr;

    if ((count = cs_disasm(disassembler->handle, (unsigned char *)buf, addr - ptr, addr, 10, &insn)) > 0)
    {
        int i;
        for (i = 0; i < count; i++)
        {
            has_read += insn[i].size;
            print_instruction(&insn[i]);
        }

        cs_free(insn, count);
    }
    else
        fprintf(stderr, "disasm error\n");

    return addr + has_read;
}
