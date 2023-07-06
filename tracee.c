#include "inc/tracee.h"

void init_tracee(tracee_t *tracee)
{
    int i;

    tracee->pid = -1;
    tracee->last_disasm_addr = 0;
    tracee->last_dump_addr = 0;
    tracee->text = NULL;
    tracee->text_section_addr.begin = 0;
    tracee->text_section_addr.end = 0;
    tracee->baseaddr = 0;
    tracee->elf_type = 0;
    memset(tracee->program_name, 0, sizeof(tracee->program_name));
    for(i = 0; i < MAX_BREAKPOINTS; i++)
        tracee->breakpoints[i].id = -1;
    return;
}

void free_tracee(tracee_t *tracee)
{
    if(tracee->text) free(tracee->text);
    init_tracee(tracee);
    return;
}

int load_elf(tracee_t *tracee, char *program_name)
{
    int i;
    elf_handle_t *eh = NULL;
    elf_shdr_t *text_shdr;
    elf_strtab_t *tab = NULL;

    elf_init();

    if((eh = elf_open(program_name)) == NULL)
    {
        fprintf(stderr, "** unable to open '%s'.\n", program_name);
        return -1;
    }

    if(elf_load_all(eh) < 0)
    {
        fprintf(stderr, "** unable to load '%s'.\n", program_name);
        if(eh)
        {
            elf_close(eh);
            eh = NULL;
        }
        return -1;
    }

    for(tab = eh->strtab; tab != NULL; tab = tab->next)
    {
        if(tab->id == eh->shstrndx) break;
    }

    if(tab == NULL)
    {
        fprintf(stderr, "** section header string table not found.\n");
        if(eh)
        {
            elf_close(eh);
            eh = NULL;
        }
		return -1;
    }

    for(i = 0; i < eh->shnum; i++)
    {
        if(strcmp(".text", &tab->data[eh->shdr[i].name]) == 0)
        {
            text_shdr = &eh->shdr[i];
            break;
        }
    }

    strcpy(tracee->program_name, program_name);
    tracee->text_shdr.addr = text_shdr->addr;
    tracee->text_shdr.size = text_shdr->size;
    tracee->text_shdr.offset = text_shdr->offset;
    tracee->text_shdr.flags = text_shdr->flags;
    tracee->text_section_addr.begin = text_shdr->addr;
    tracee->text_section_addr.end = text_shdr->addr+text_shdr->size;
    tracee->baseaddr = 0;
    tracee->elf_type = eh->ehdr.ptr64->e_type;
    tracee->text = (unsigned char *) malloc(text_shdr->size * sizeof(unsigned char *));

    if(lseek(eh->fd, text_shdr->offset, SEEK_SET) < 0)
        error_quit("move to text section error");
    if(read(eh->fd, tracee->text, text_shdr->size) < 0)
        error_quit("read text section error");

    fprintf(stderr, "** program '%s' load. ", program_name);
    fprintf(stderr, "entry point: 0x%-lx, vaddr: 0x%-llx, offset: 0x%-llx, size: 0x%llx\n",
            eh->entrypoint,
            text_shdr->addr,
            text_shdr->offset,
            text_shdr->size);

    if(eh)
    {
        elf_close(eh);
        eh = NULL;
    }
    return 0;
}

int create_tracee_process(tracee_t *tracee)
{
    pid_t child;
    int wait_status;
    if((child = fork()) < 0) {
        error_quit("fork error");
    }
    if(child == 0) {
        if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
            error_quit("ptrace PTRACE_TRACEME error");
        }

        char *args[] = { NULL };
        execvp(tracee->program_name, args);
        perror("execvp error");
        fprintf(stderr, "** if the program is at the current directory, try './<program_path>' as your path.\n");
        exit(EXIT_FAILURE);
    }
    else {
        if(waitpid(child, &wait_status, 0) < 0) {
            error_quit("waitpid");
        }
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
        if(!WIFSTOPPED(wait_status)) {
            error_quit("ptrace_setoptions error");
        }

        tracee->pid = child;
    }

    return child;
}

int is_tracee_exit(tracee_t *tracee, int wait_status)
{
    if(WIFEXITED(wait_status))
    {
        fprintf(stderr, "** child process %d terminated normally (code %u)\n", tracee->pid, WEXITSTATUS(wait_status));
        return 1;
    }
    return 0;
}

void tracee_single_step(tracee_t *tracee, int *wait_status)
{
    if(ptrace(PTRACE_SINGLESTEP, tracee->pid, 0, 0) < 0)
        error_quit("ptrace single step error");
    if(waitpid(tracee->pid, wait_status, 0) < 0)
        error_quit("waitpid");
    return;
}

int hit_breakpoint(tracee_t *tracee, unsigned long long address)
{
    breakpoint_t *bp = tracee->breakpoints;

    int i;
    for(i = 0; i < MAX_BREAKPOINTS; i++)
    {
        if(bp[i].id == -1) continue;

        if((bp[i].address+tracee->baseaddr) == address)
            return i;
    }

    return -1;
}

int set_breakpoint(tracee_t *tracee, unsigned long long target_addr, unsigned long long *code)
{
    // get original text
    if((*code = ptrace(PTRACE_PEEKTEXT, tracee->pid, target_addr+tracee->baseaddr, 0)) < 0) {
        perror("get code error");
        return -1;
    }

    // set break points
    if(ptrace(PTRACE_POKETEXT, tracee->pid, target_addr+tracee->baseaddr, (*code & BYTE_MASK) | 0xcc) < 0) {
        perror("insert breakpoint error");
        return -1;
    }

    return 0;
}

int restore_code(tracee_t *tracee, struct user_regs_struct *regs, int bpoint_id, int reset)
{
    breakpoint_t *bp = tracee->breakpoints;
    unsigned long long code = 0;

    // get current code
    if((code = ptrace(PTRACE_PEEKTEXT, tracee->pid, bp[bpoint_id].address+tracee->baseaddr, 0)) < 0) {
        perror("get current code error");
        return -1;
    }

    // restore the code
    if(ptrace(PTRACE_POKETEXT, tracee->pid, bp[bpoint_id].address+tracee->baseaddr, (code & BYTE_MASK) | bp[bpoint_id].origin_code) < 0)
    {
        perror("restore code error");
        return -1;
    }

    // reset rip
    if(reset)
    {
        regs->rip -= 1;
        if(ptrace(PTRACE_SETREGS, tracee->pid, 0, regs) < 0)
        {
            perror("restore rip error");
            return -1;
        }
    }

    return 0;
}

int find_breakpoint(tracee_t *tracee, int id)
{
    breakpoint_t *bp = tracee->breakpoints;

    int i;
    for(i = 0; i < MAX_BREAKPOINTS; i++)
    {
        if(bp[i].id == id)
            return i;
    }

    return -1;
}

void add_breakpoint_to_list(tracee_t *tracee, unsigned long long address, unsigned long long code)
{
    breakpoint_t *bp = tracee->breakpoints;
    unsigned char *cptr = (unsigned char *) &code;

    int i;
    for(i = 0; i < MAX_BREAKPOINTS; i++)
    {
        if(bp[i].id == -1)
        {
            bp[i].id = i;
            bp[i].address = address;
            bp[i].origin_code = cptr[0];
            break;
        }
    }

    return;
}

void delete_breakpoint_from_list(tracee_t *tracee, int id)
{
    breakpoint_t *bp = tracee->breakpoints;
    int i;
    for(i = 0; i < MAX_BREAKPOINTS; i++)
    {
        if(bp[i].id == id)
        {
            bp[i].id = -1;
            fprintf(stderr, "breakpoint %d deleted.\n", id);
            return;
        }
    }

    fprintf(stderr, "** can not find the breakpoint %d.\n", id);
    return;
}

void disable_all_breakpoints(tracee_t *tracee)
{
    breakpoint_t *bp = tracee->breakpoints;
    unsigned long long code = 0;

    int i;
    for(i = 0; i < MAX_BREAKPOINTS; i++)
    {
        if(bp[i].id == -1) continue;

        // get current code
        if((code = ptrace(PTRACE_PEEKTEXT, tracee->pid, bp[i].address+tracee->baseaddr, 0)) < 0) {
            perror("get current code error");
            return;
        }

        // restore the code
        if(ptrace(PTRACE_POKETEXT, tracee->pid, bp[i].address+tracee->baseaddr, (code & BYTE_MASK) | bp[i].origin_code) < 0)
        {
            perror("restore code error");
            return;
        }
    }

    return;
}

void enable_all_breakpoints(tracee_t *tracee)
{
    breakpoint_t *bp = tracee->breakpoints;
    unsigned long long code = 0;

    int i;
    for(i = 0; i < MAX_BREAKPOINTS; i++)
    {
        if(bp[i].id == -1) continue;

        // get current code
        if((code = ptrace(PTRACE_PEEKTEXT, tracee->pid, bp[i].address+tracee->baseaddr, 0)) < 0) {
            perror("get current code error");
            return;
        }

        // set break points
        if(ptrace(PTRACE_POKETEXT, tracee->pid, bp[i].address+tracee->baseaddr, (code & BYTE_MASK) | 0xcc) < 0) {
            perror("insert breakpoint error");
            return;
        }
    }

    return;
}

void get_breakpoints_origin_code(tracee_t *tracee)
{
    breakpoint_t *bp = tracee->breakpoints;
    unsigned long long code = 0;
    unsigned char *cptr = (unsigned char *) &code;

    int i;
    for(i = 0; i < MAX_BREAKPOINTS; i++)
    {
        if(bp[i].id == -1) continue;

        // get original text
        if((code = ptrace(PTRACE_PEEKTEXT, tracee->pid, bp[i].address+tracee->baseaddr, 0)) < 0) {
            perror("get origin code error");
            return;
        }

        bp[i].origin_code = cptr[0];
    }

    return;
}

void print_breakpoint_list(tracee_t *tracee)
{
    breakpoint_t *bp = tracee->breakpoints;

    int i;
    for(i = 0; i < MAX_BREAKPOINTS; i++)
    {
        if(bp[i].id == -1) continue;

        fprintf(stderr, "  %d:  0x%06llx\n", bp[i].id, bp[i].address+tracee->baseaddr);
    }
    return;
}
