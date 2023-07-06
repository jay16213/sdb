#ifndef __COMMAND_H_
#define __COMMAND_H_

#include <string.h>
#include <stdio.h>

#include "fsm.h"

#define PARSE_ERROR   -1
#define PARSE_OK       0

#define COMMAND_BREAK    1
#define COMMAND_CONTINUE 2
#define COMMAND_DELETE   3
#define COMMAND_DISASM   4
#define COMMAND_DUMP     5
#define COMMAND_EXIT     6
#define COMMAND_GET      7
#define COMMAND_GETREGS  8
#define COMMAND_HELP     9
#define COMMAND_LIST    10
#define COMMAND_LOAD    11
#define COMMAND_RUN     12
#define COMMAND_VMMAP   13
#define COMMAND_SET     14
#define COMMAND_SI      15
#define COMMAND_START   16

#define ERROR_COMMAND_NOT_FOUND            1
#define ERROR_STATE_NOT_INIT               2
#define ERROR_STATE_NOT_LOADED             3
#define ERROR_STATE_NOT_RUNNING            4
#define ERROR_STATE_NOT_LOADED_NOR_RUNNING 5

int parse_command(char *command, const int debugger_state, int *result);
void print_command_error(int code);

#endif
