#include "inc/disasm-tool.h"

void disassembler_open(csh *handle)
{
    if (cs_open(CS_ARCH_X86, CS_MODE_64, handle) != CS_ERR_OK)
        cs_errno(*handle);

    return;
}

void disassembler_close(csh *handle)
{
    cs_close(handle);
    return;
}

void disassemble_at_break(tracee_t *tracee, csh handle, int hit_id)
{
    breakpoint_t *bp = tracee->breakpoints;
    int count;
    unsigned long long has_read = 0;
    unsigned long long code = 0;
    unsigned long long addr = bp[hit_id].address + tracee->baseaddr;
    unsigned char *cptr = (unsigned char *)&code;
    cs_insn *insn;

    // get current code
    if ((code = ptrace(PTRACE_PEEKTEXT, tracee->pid, addr, 0)) < 0)
    {
        perror("get current code error");
        return;
    }

    code = (code & BYTE_MASK) | bp[hit_id].origin_code;

    if ((count = cs_disasm(handle, cptr, sizeof(unsigned long long), addr, 1, &insn)) > 0)
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

unsigned long long disassemble(csh handle, unsigned char *code, unsigned long long code_size, unsigned long long addr, int disasm_size)
{
    int count;
    unsigned long long has_read = 0;
    cs_insn *insn;

    if ((count = cs_disasm(handle, code, code_size, addr, disasm_size, &insn)) > 0)
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

unsigned long long disassemble_in_running(
    tracee_t *tracee,
    csh handle,
    unsigned long long addr)
{
    int count;
    unsigned long long has_read = 0;
    char buf[80] = {0};
    // unsigned long long addr = baseaddr + offset;
    unsigned long long ptr = addr;
    cs_insn *insn;

    for (ptr = addr; ptr < addr + sizeof(buf); ptr += PEEKSIZE)
    {
        long long peek;
        errno = 0;
        peek = ptrace(PTRACE_PEEKTEXT, tracee->pid, ptr, NULL);
        if (errno != 0)
            break;
        memcpy(&buf[ptr - addr], &peek, PEEKSIZE);
    }

    if (ptr == addr)
        return addr;

    if ((count = cs_disasm(handle, (unsigned char *)buf, addr - ptr, addr, 10, &insn)) > 0)
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

void print_instruction(cs_insn *insn)
{
    int i;
    char bytes[160] = "";

    for (i = 0; i < insn->size; i++)
        snprintf(&bytes[i * 3], 4, "%2.2x ", insn->bytes[i]);
    fprintf(stderr, "%12lx: %-32s\t%-10s%s\n", insn->address, bytes, insn->mnemonic, insn->op_str);

    return;
}
