#include "inc/vmmap.h"

int load_maps(tracee_t *tracee, int print_result)
{
    char fn[128];
    char buf[256];
    FILE *fp;

    snprintf(fn, sizeof(fn), "/proc/%u/maps", tracee->pid);
    if ((fp = fopen(fn, "rt")) == NULL)
        return -1;

    while (fgets(buf, sizeof(buf), fp) != NULL)
    {
        int nargs = 0;
        char *token, *saveptr, *args[8], *ptr = buf;
        char perm_str[4];
        memset(perm_str, '-', sizeof(perm_str));
        perm_str[3] = '\0';

        while (nargs < 8 && (token = strtok_r(ptr, " \t\n\r", &saveptr)) != NULL)
        {
            args[nargs++] = token;
            ptr = NULL;
        }

        map_entry_t m;

        if ((ptr = strchr(args[0], '-')) != NULL)
        {
            *ptr = '\0';
            m.range.begin = strtol(args[0], NULL, 16);
            m.range.end = strtol(ptr + 1, NULL, 16);
        }

        m.perm = 0;
        if (args[1][0] == 'r')
        {
            m.perm |= 0x04;
            perm_str[0] = 'r';
        }
        if (args[1][1] == 'w')
        {
            m.perm |= 0x02;
            perm_str[1] = 'w';
        }
        if (args[1][2] == 'x')
        {
            m.perm |= 0x01;
            perm_str[2] = 'x';
        }

        m.offset = strtol(args[2], NULL, 16);

        if (print_result)
        {
            fprintf(stderr, "%016lx-%016lx %s %lu\t\t%s\n",
                    m.range.begin, m.range.end,
                    perm_str,
                    m.offset,
                    nargs >= 6 ? args[5] : "");
        }

        if (nargs >= 6)
        {
            if (strcmp(basename(args[5]), basename(tracee->program_name)) == 0 && m.offset == 0 && (m.perm & 0x01) == 0x01)
            {
                tracee->baseaddr = m.range.begin;
            }
        }
    }

    if (tracee->elf_type == ET_EXEC)
        tracee->baseaddr = 0;

    tracee->text_phaddr.begin = tracee->baseaddr + tracee->text_section_addr.begin;
    tracee->text_phaddr.end = tracee->baseaddr + tracee->text_section_addr.end;

    return 0;
}
