#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include "inc/disasm-tool.h"
#include "inc/command.h"
#include "inc/tracee.h"
#include "inc/vmmap.h"
#include "inc/util.h"

static int debugger_state;

int main(int argc, char *argv[])
{
    char user_input[256];
    char *command = NULL, *args = NULL;
    int result = 0;
    tracee_t tracee;
    struct user_regs_struct regs;
    int wait_status;
    int hit = 0, hit_id = -1;
    disassembler_t *disasmbler;

    FSM_STATE_TRANS(debugger_state, STATE_INIT);
    init_tracee(&tracee);

    disasmbler = disasm_init(&tracee);

    if (argc >= 2)
    {
        if (load_elf(&tracee, argv[1]) == 0)
        {
            FSM_STATE_TRANS(debugger_state, STATE_LOADED);
            hit = 0;
            hit_id = -1;
        }
    }

    while (1)
    {
        printf("sdb> ");
        memset(user_input, '\0', sizeof(user_input));
        fgets(user_input, 256, stdin);
        command = strtok(user_input, DELIMETER);
        if (command == NULL)
            continue;

        if (parse_command(command, debugger_state, &result) != PARSE_OK)
        {
            print_command_error(result);
            continue;
        }

        switch (result)
        {
        case COMMAND_BREAK:
        {
            if ((args = strtok(NULL, DELIMETER)) == NULL)
            {
                fprintf(stderr, "** usage: break {instruction-address}\n");
                continue;
            }

            // load vmmap
            load_maps(&tracee, 0);

            unsigned long long target = strtoull(args, NULL, 0);
            unsigned long long code = 0;

            if (debugger_state == STATE_RUNNING)
            {
                if (!inside_range(target, tracee.text_phaddr))
                {
                    fprintf(stderr, "** the address should be within the range specified by the text segment.\n");
                    continue;
                }

                if (set_breakpoint(&tracee, target, &code) == 0)
                    add_breakpoint_to_list(&tracee, target, code);
            }
            else // loading state
            {
                if (!inside_range(target, tracee.text_section_addr))
                {
                    fprintf(stderr, "** the address should be within the range specified by the text segment in the ELF file.\n");
                    continue;
                }

                add_breakpoint_to_list(&tracee, target, code);
            }

            break;
        }

        case COMMAND_RUN:
        {
            if (debugger_state == STATE_RUNNING)
                fprintf(stderr, "** program '%s' is already running.\n", tracee.program_name);
            else
            {
                create_tracee_process(&tracee);
                load_maps(&tracee, 0);
                get_breakpoints_origin_code(&tracee);
                enable_all_breakpoints(&tracee);
                tracee.last_disasm_addr = 0;
                tracee.last_dump_addr = 0;
                FSM_STATE_TRANS(debugger_state, STATE_RUNNING);

                fprintf(stderr, "** pid %d\n", tracee.pid);
            }
            // no break at COMMAND_RUN case: run & continue command share the same handle logic
        }
        case COMMAND_CONTINUE:
        {
            if (hit)
            {
                tracee_single_step(&tracee, &wait_status);
                if (is_tracee_exit(&tracee, wait_status))
                {
                    tracee.baseaddr = 0;
                    FSM_STATE_TRANS(debugger_state, STATE_LOADED);
                }
                else
                    enable_all_breakpoints(&tracee);
                hit = 0;
                hit_id = -1;
            }

            ptrace(PTRACE_CONT, tracee.pid, 0, 0);
            if (waitpid(tracee.pid, &wait_status, 0) > 0)
            {
                if (is_tracee_exit(&tracee, wait_status))
                {
                    tracee.baseaddr = 0;
                    FSM_STATE_TRANS(debugger_state, STATE_LOADED);
                }
                else
                {
                    get_register_values(tracee.pid, &regs);

                    if ((hit_id = hit_breakpoint(&tracee, regs.rip - 1)) >= 0)
                    {
                        fprintf(stderr, "** breakpoint @ ");
                        disasm_at_break(disasmbler, hit_id);
                        restore_code(&tracee, &regs, hit_id, 1);
                        hit = 1;
                    }
                }
            }
            break;
        }
        case COMMAND_DELETE:
        {
            args = strtok(NULL, DELIMETER);
            if (args == NULL)
            {
                fprintf(stderr, "** usage: delete {break-point-id}\n");
                continue;
            }

            int id = atoi(args);
            if (find_breakpoint(&tracee, id) < 0)
            {
                fprintf(stderr, "** can not find breakpoint %d.\n", id);
                continue;
            }

            if (hit_id == id)
            {
                hit = 0;
                hit_id = -1;
            }
            else
            {
                if (debugger_state == STATE_RUNNING)
                {
                    get_register_values(tracee.pid, &regs);
                    restore_code(&tracee, &regs, id, 0);
                }
            }
            delete_breakpoint_from_list(&tracee, id);
            break;
        }
        case COMMAND_DISASM:
        {
            unsigned long long addr;

            args = strtok(NULL, DELIMETER);

            if (debugger_state == STATE_LOADED)
            {
                if (args == NULL)
                {
                    if (tracee.last_disasm_addr == 0)
                    {
                        fprintf(stderr, "** no addr is given.\n");
                        continue;
                    }
                    else
                    {
                        if (tracee.last_disasm_addr >= tracee.text_section_addr.end)
                        {
                            fprintf(stderr, "** reach the end of the text section.\n");
                            fprintf(stderr, "** the debugger will go back to the begin of the text section and continue disassembling.\n");
                            tracee.last_disasm_addr = tracee.text_section_addr.begin;
                        }
                        addr = tracee.last_disasm_addr;
                    }
                }
                else
                {
                    addr = strtoull(args, NULL, 0);
                    if (!inside_range(addr, tracee.text_section_addr))
                    {
                        fprintf(stderr,
                                "** the address should be within the range specified by the text segment in the ELF file\n");
                        continue;
                    }
                }
                unsigned long long offset = (addr - tracee.text_section_addr.begin);
                tracee.last_disasm_addr = disasm(disasmbler, tracee.text + offset, tracee.text_shdr.size - offset, addr, 10);
            }
            else // running state
            {
                if (args == NULL)
                {
                    if (tracee.last_disasm_addr == 0)
                    {
                        fprintf(stderr, "** no addr is given.\n");
                        continue;
                    }
                    else
                        addr = tracee.last_disasm_addr;
                }
                else
                    addr = strtoull(args, NULL, 0);

                disable_all_breakpoints(&tracee);
                tracee.last_disasm_addr = disasm_in_running(disasmbler, addr);
                enable_all_breakpoints(&tracee);
            }
            break;
        }
        case COMMAND_DUMP:
        {
            unsigned long long addr;

            load_maps(&tracee, 0);

            if ((args = strtok(NULL, DELIMETER)) == NULL)
            {
                if (tracee.last_dump_addr == 0)
                {
                    fprintf(stderr, "** no addr is given.\n");
                    continue;
                }
                else
                    addr = tracee.last_dump_addr;
            }
            else
                addr = strtoull(args, NULL, 0);

            tracee.last_dump_addr = dump_code(tracee.pid, addr);
            break;
        }
        case COMMAND_EXIT:
        {
            disasm_finalize(disasmbler);
            free_tracee(&tracee);
            exit(EXIT_SUCCESS);
        }
        case COMMAND_GET:
        {
            if ((args = strtok(NULL, DELIMETER)) == NULL)
            {
                fprintf(stderr, "** usage: get {reg}. Register names are all in lowercase\n");
                continue;
            }

            get_register_values(tracee.pid, &regs);
            print_register_value(&regs, args);
            break;
        }
        case COMMAND_GETREGS:
        {
            get_register_values(tracee.pid, &regs);
            print_register_value(&regs, NULL);
            break;
        }
        case COMMAND_HELP:
        {
            help_msg();
            break;
        }
        case COMMAND_LIST:
        {
            print_breakpoint_list(&tracee);
            break;
        }
        case COMMAND_LOAD:
        {
            if ((args = strtok(NULL, DELIMETER)) == NULL)
            {
                fprintf(stderr, "** usage: load {path to a program}\n");
                continue;
            }

            init_tracee(&tracee);

            if (load_elf(&tracee, args) == 0)
            {
                FSM_STATE_TRANS(debugger_state, STATE_LOADED);
                hit = 0;
                hit_id = -1;
            }
            break;
        }
        case COMMAND_VMMAP:
        {
            if (debugger_state == STATE_LOADED)
            {
                // TODO: fix access permission
                fprintf(stderr, "%016llx-%016llx r-x %llx\t%s\n",
                        tracee.text_section_addr.begin,
                        tracee.text_section_addr.end,
                        tracee.text_shdr.offset,
                        tracee.program_name);
            }
            else
                load_maps(&tracee, 1);
            break;
        }
        case COMMAND_SET:
        {
            // get register name
            char *reg_name;
            if ((reg_name = strtok(NULL, DELIMETER)) == NULL)
            {
                fprintf(stderr, "** usage: set reg val\n");
                continue;
            }

            // get value
            if ((args = strtok(NULL, DELIMETER)) == NULL)
            {
                fprintf(stderr, "** usage: set reg val\n");
                continue;
            }

            unsigned long long val = strtoull(args, NULL, 0);

            get_register_values(tracee.pid, &regs);

            if (set_register_value(&regs, reg_name, val) < 0)
            {
                fprintf(stderr, "** no register named '%s'.\n", reg_name);
                continue;
            }

            if (ptrace(PTRACE_SETREGS, tracee.pid, 0, &regs) < 0)
                perror("set error");
            break;
        }
        case COMMAND_SI:
        {
            tracee_single_step(&tracee, &wait_status);

            if (is_tracee_exit(&tracee, wait_status))
            {
                tracee.baseaddr = 0;
                FSM_STATE_TRANS(debugger_state, STATE_LOADED);
            }
            else
            {
                if (hit)
                {
                    enable_all_breakpoints(&tracee);
                    hit = 0;
                    hit_id = -1;
                }
                else
                {
                    get_register_values(tracee.pid, &regs);

                    if ((hit_id = hit_breakpoint(&tracee, regs.rip - 1)) >= 0)
                    {
                        fprintf(stderr, "** breakpoint @ ");
                        disasm_at_break(disasmbler, hit_id);
                        restore_code(&tracee, &regs, hit_id, 1);
                        hit = 1;
                    }
                }
            }
            break;
        }
        case COMMAND_START:
        {
            create_tracee_process(&tracee);
            load_maps(&tracee, 0);
            get_breakpoints_origin_code(&tracee);
            enable_all_breakpoints(&tracee);
            tracee.last_disasm_addr = 0;
            tracee.last_dump_addr = 0;
            FSM_STATE_TRANS(debugger_state, STATE_RUNNING);

            fprintf(stderr, "** pid %d\n", tracee.pid);
            break;
        }
        }
    }

    return 0;
}
