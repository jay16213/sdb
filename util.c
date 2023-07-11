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
            fprintf(stderr, "%s = %llu (0x%llx)\n", #target_reg_name, regs->target_reg_name, regs->target_reg_name); \
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
        fprintf(stderr, "** No register named '%s'\n", reg_name);
    }
    else
    {
        fprintf(stderr, "RAX %-16llx\tRBX %-16llx\tRCX %-16llx\tRDX %-16llx\n", regs->rax, regs->rbx, regs->rcx, regs->rdx);
        fprintf(stderr, "R8  %-16llx\tR9  %-16llx\tR10 %-16llx\tR11 %-16llx\n", regs->r8, regs->r9, regs->r10, regs->r11);
        fprintf(stderr, "R12 %-16llx\tR13 %-16llx\tR14 %-16llx\tR15 %-16llx\n", regs->r12, regs->r13, regs->r14, regs->r15);
        fprintf(stderr, "RDI %-16llx\tRSI %-16llx\tRBP %-16llx\tRSP %-16llx\n", regs->rdi, regs->rsi, regs->rbp, regs->rsp);
        fprintf(stderr, "RIP %-16llx\tFLAGS %016llx\n", regs->rip, regs->eflags);
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
    printf("  - break {instruction-address}: add a break point\n");
    printf("  - cont: continue execution\n");
    printf("  - delete {break-point-id}: remove a break point\n");
    printf("  - disasm addr: disassemble instructions in a file or a memory region\n");
    printf("  - dump addr [length]: dump memory content\n");
    printf("  - exit: terminate the debugger\n");
    printf("  - get reg: get a single value from a register\n");
    printf("  - getregs: show registers\n");
    printf("  - help: show this message\n");
    printf("  - list: list break points\n");
    printf("  - load {path/to/a/program}: load a program\n");
    printf("  - run: run the program\n");
    printf("  - vmmap: show memory layout\n");
    printf("  - set reg val: get a single value to a register\n");
    printf("  - si: step into instruction\n");
    printf("  - start: start the program and stop at the first instruction\n");
    return;
}

unsigned long long dump_code(pid_t tracee, unsigned long long addr)
{
    unsigned char buf[80] = {0};
    unsigned long long has_read = 0;
    unsigned long long ptr = addr;
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
        fprintf(stderr, "%12llx:", ptr);
        for (j = 0; j < 16; j++)
            fprintf(stderr, " %2.2x", buf[i * 16 + j]);

        fprintf(stderr, "  |");

        for (j = 0; j < 16; j++)
        {
            fprintf(stderr, "%c", isprint(buf[i * 16 + j]) ? buf[i * 16 + j] : '.');
        }

        fprintf(stderr, "|\n");
    }

    return addr + has_read;
}
