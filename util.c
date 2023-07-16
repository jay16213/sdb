#include "inc/util.h"

void error_quit(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

int inside_range(unsigned long long target, range_t range)
{
    return target >= range.begin && target <= range.end;
}

#define PRINT_REG_VAL(regs, target_reg_name, user_input_name)                                                        \
    {                                                                                                                \
        if (strcmp(#target_reg_name, user_input_name) == 0)                                                          \
        {                                                                                                            \
            SDB_INFO("%s = %llu (0x%llx)\n", #target_reg_name, regs->target_reg_name, regs->target_reg_name); \
            return;                                                                                                  \
        }                                                                                                            \
    }

void print_register_value(struct user_regs_struct *regs, char *reg_name)
{
    if (reg_name)
    {
        PRINT_REG_VAL(regs, r15, reg_name);
        PRINT_REG_VAL(regs, r14, reg_name);
        PRINT_REG_VAL(regs, r13, reg_name);
        PRINT_REG_VAL(regs, r12, reg_name);
        PRINT_REG_VAL(regs, rbp, reg_name);
        PRINT_REG_VAL(regs, rbx, reg_name);
        PRINT_REG_VAL(regs, r11, reg_name);
        PRINT_REG_VAL(regs, r10, reg_name);
        PRINT_REG_VAL(regs, r9, reg_name);
        PRINT_REG_VAL(regs, r8, reg_name);
        PRINT_REG_VAL(regs, rax, reg_name);
        PRINT_REG_VAL(regs, rcx, reg_name);
        PRINT_REG_VAL(regs, rdx, reg_name);
        PRINT_REG_VAL(regs, rsi, reg_name);
        PRINT_REG_VAL(regs, rdi, reg_name);
        PRINT_REG_VAL(regs, rip, reg_name);
        PRINT_REG_VAL(regs, rsp, reg_name);
        PRINT_REG_VAL(regs, eflags, reg_name);
        SDB_ERROR("** No register named '%s'\n", reg_name);
    }
    else
    {
        SDB_INFO("RAX %-16llx\tRBX %-16llx\tRCX %-16llx\tRDX %-16llx\n", regs->rax, regs->rbx, regs->rcx, regs->rdx);
        SDB_INFO("R8  %-16llx\tR9  %-16llx\tR10 %-16llx\tR11 %-16llx\n", regs->r8, regs->r9, regs->r10, regs->r11);
        SDB_INFO("R12 %-16llx\tR13 %-16llx\tR14 %-16llx\tR15 %-16llx\n", regs->r12, regs->r13, regs->r14, regs->r15);
        SDB_INFO("RDI %-16llx\tRSI %-16llx\tRBP %-16llx\tRSP %-16llx\n", regs->rdi, regs->rsi, regs->rbp, regs->rsp);
        SDB_INFO("RIP %-16llx\tFLAGS %016llx\n", regs->rip, regs->eflags);
    }

    return;
}

#define SET_REG_VAL(regs, target_reg_name, user_input_name, val) \
    {                                                            \
        if (strcmp(#target_reg_name, user_input_name) == 0)      \
        {                                                        \
            regs->target_reg_name = val;                         \
            return 0;                                            \
        }                                                        \
    }

int set_register_value(struct user_regs_struct *regs, char *reg_name, unsigned long long val)
{
    SET_REG_VAL(regs, r15, reg_name, val);
    SET_REG_VAL(regs, r14, reg_name, val);
    SET_REG_VAL(regs, r13, reg_name, val);
    SET_REG_VAL(regs, r12, reg_name, val);
    SET_REG_VAL(regs, r11, reg_name, val);
    SET_REG_VAL(regs, r10, reg_name, val);
    SET_REG_VAL(regs, r9, reg_name, val);
    SET_REG_VAL(regs, r8, reg_name, val);
    SET_REG_VAL(regs, rax, reg_name, val);
    SET_REG_VAL(regs, rbx, reg_name, val);
    SET_REG_VAL(regs, rcx, reg_name, val);
    SET_REG_VAL(regs, rdx, reg_name, val);
    SET_REG_VAL(regs, rdi, reg_name, val);
    SET_REG_VAL(regs, rsi, reg_name, val);
    SET_REG_VAL(regs, rbp, reg_name, val);
    SET_REG_VAL(regs, rsp, reg_name, val);
    SET_REG_VAL(regs, rip, reg_name, val);
    SET_REG_VAL(regs, rdi, reg_name, val);
    SET_REG_VAL(regs, rdi, reg_name, val);
    SET_REG_VAL(regs, eflags, reg_name, val);
    return -1;
}

void get_register_values(pid_t tracee, struct user_regs_struct *regs)
{
    if (ptrace(PTRACE_GETREGS, tracee, 0, regs) < 0)
        perror("ptrace get regs error");
    return;
}

void help_msg()
{
    SDB_INFO("  - break {instruction-address}: add a break point\n");
    SDB_INFO("  - cont: continue execution\n");
    SDB_INFO("  - delete {break-point-id}: remove a break point\n");
    SDB_INFO("  - disasm addr: disassemble instructions in a file or a memory region\n");
    SDB_INFO("  - dump addr [length]: dump memory content\n");
    SDB_INFO("  - exit: terminate the debugger\n");
    SDB_INFO("  - get reg: get a single value from a register\n");
    SDB_INFO("  - getregs: show registers\n");
    SDB_INFO("  - help: show this message\n");
    SDB_INFO("  - list: list break points\n");
    SDB_INFO("  - load {path/to/a/program}: load a program\n");
    SDB_INFO("  - run: run the program\n");
    SDB_INFO("  - vmmap: show memory layout\n");
    SDB_INFO("  - set reg val: get a single value to a register\n");
    SDB_INFO("  - si: step into instruction\n");
    SDB_INFO("  - start: start the program and stop at the first instruction\n");
}

uint64_t dump_code(pid_t tracee, uint64_t addr)
{
    unsigned char buf[80] = {0};
    uint64_t has_read = 0;
    uint64_t ptr = addr;
    int i, j;

    for (i = 0; i < 10; i++, ptr += 8)
    {
        long long peek;
        errno = 0;
        peek = ptrace(PTRACE_PEEKTEXT, tracee, ptr, NULL);
        if (errno != 0)
            break;
        memcpy(&buf[i * 8], &peek, 8);
        has_read += 8;
    }

    for (i = 0, ptr = addr; i < 5; i++, ptr += 16)
    {
        SDB_INFO("%12lx:", ptr);
        for (j = 0; j < 16; j++)
            SDB_INFO(" %2.2x", buf[i * 16 + j]);

        SDB_INFO("  |");

        for (j = 0; j < 16; j++)
        {
            SDB_INFO("%c", isprint(buf[i * 16 + j]) ? buf[i * 16 + j] : '.');
        }

        SDB_INFO("|\n");
    }

    return addr + has_read;
}

void print_instruction(cs_insn *insn)
{
    int i;
    char bytes[160] = "";

    for (i = 0; i < insn->size; i++)
        snprintf(&bytes[i * 3], 4, "%2.2x ", insn->bytes[i]);
    SDB_INFO("%12lx: %-32s\t%-10s%s\n", insn->address, bytes, insn->mnemonic, insn->op_str);

    return;
}
