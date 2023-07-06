#include "inc/command.h"

#define MATCH_STR(str1, str2) strcmp(str1, str2) == 0

int parse_command(char *command, const int debugger_state, int *result)
{
    if(MATCH_STR("break", command) || MATCH_STR("b", command))
    {
        if(debugger_state != STATE_LOADED && debugger_state != STATE_RUNNING)
        {
            *result = ERROR_STATE_NOT_LOADED_NOR_RUNNING;
            return PARSE_ERROR;
        }

        *result = COMMAND_BREAK;
        return PARSE_OK;
    }

    if(MATCH_STR("cont", command) || MATCH_STR("c", command))
    {
        if(debugger_state != STATE_RUNNING)
        {
            *result = ERROR_STATE_NOT_RUNNING;
            return PARSE_ERROR;
        }

        *result = COMMAND_CONTINUE;
        return PARSE_OK;
    }

    if(MATCH_STR("delete", command))
    {
        *result = COMMAND_DELETE;
        return PARSE_OK;
    }

    if(MATCH_STR("disasm", command) || MATCH_STR("d", command))
    {
        if(debugger_state != STATE_LOADED && debugger_state != STATE_RUNNING)
        {
            *result = ERROR_STATE_NOT_LOADED_NOR_RUNNING;
            return PARSE_ERROR;
        }

        *result = COMMAND_DISASM;
        return PARSE_OK;
    }

    if(MATCH_STR("dump", command) || MATCH_STR("x", command))
    {
        if(debugger_state != STATE_RUNNING)
        {
            *result = ERROR_STATE_NOT_RUNNING;
            return PARSE_ERROR;
        }

        *result = COMMAND_DUMP;
        return PARSE_OK;
    }

    if(MATCH_STR("exit", command) || MATCH_STR("q", command))
    {
        *result = COMMAND_EXIT;
        return PARSE_OK;
    }

    if(MATCH_STR("get", command) || MATCH_STR("g", command))
    {
        if(debugger_state != STATE_RUNNING)
        {
            *result = ERROR_STATE_NOT_RUNNING;
            return PARSE_ERROR;
        }

        *result = COMMAND_GET;
        return PARSE_OK;
    }

    if(MATCH_STR("getregs", command))
    {
        if(debugger_state != STATE_RUNNING)
        {
            *result = ERROR_STATE_NOT_RUNNING;
            return PARSE_ERROR;
        }

        *result = COMMAND_GETREGS;
        return PARSE_OK;
    }

    if(MATCH_STR("help", command) || MATCH_STR("h", command))
    {
        *result = COMMAND_HELP;
        return PARSE_OK;
    }

    if(MATCH_STR("list", command) || MATCH_STR("l", command))
    {
        *result = COMMAND_LIST;
        return PARSE_OK;
    }

    if(MATCH_STR("load", command))
    {
        if(debugger_state != STATE_INIT)
        {
            *result = ERROR_STATE_NOT_INIT;
            return PARSE_ERROR;
        }

        *result = COMMAND_LOAD;
        return PARSE_OK;
    }

    if(MATCH_STR("run", command) || MATCH_STR("r", command))
    {
        if(debugger_state != STATE_LOADED && debugger_state != STATE_RUNNING)
        {
            *result = ERROR_STATE_NOT_LOADED_NOR_RUNNING;
            return PARSE_ERROR;
        }

        *result = COMMAND_RUN;
        return PARSE_OK;
    }

    if(MATCH_STR("vmmap", command) || MATCH_STR("m", command))
    {
        if(debugger_state != STATE_LOADED && debugger_state != STATE_RUNNING)
        {
            *result = ERROR_STATE_NOT_LOADED_NOR_RUNNING;
            return PARSE_ERROR;
        }

        *result = COMMAND_VMMAP;
        return PARSE_OK;
    }

    if(MATCH_STR("set", command) || MATCH_STR("s", command))
    {
        if(debugger_state != STATE_RUNNING)
        {
            *result = ERROR_STATE_NOT_RUNNING;
            return PARSE_ERROR;
        }

        *result = COMMAND_SET;
        return PARSE_OK;
    }

    if(MATCH_STR("si", command))
    {
        if(debugger_state != STATE_RUNNING)
        {
            *result = ERROR_STATE_NOT_RUNNING;
            return PARSE_ERROR;
        }

        *result = COMMAND_SI;
        return PARSE_OK;
    }

    if(MATCH_STR("start", command))
    {
        if(debugger_state != STATE_LOADED)
        {
            *result = ERROR_STATE_NOT_LOADED;
            return PARSE_ERROR;
        }

        *result = COMMAND_START;
        return PARSE_OK;
    }

    *result = ERROR_COMMAND_NOT_FOUND;
    return PARSE_ERROR;
}

void print_command_error(int code)
{
    switch (code)
    {
        case ERROR_COMMAND_NOT_FOUND:
            fprintf(stderr, "** command not found.\n");
            break;
        case ERROR_STATE_NOT_INIT:
            fprintf(stderr, "** has already loaded one prgram.\n");
            break;
        case ERROR_STATE_NOT_LOADED:
            fprintf(stderr, "** no program is loaded.\n");
            break;
        case ERROR_STATE_NOT_RUNNING:
            fprintf(stderr, "** no program is running.\n");
            break;
        case ERROR_STATE_NOT_LOADED_NOR_RUNNING:
            fprintf(stderr, "** no program is loaded or running.\n");
            break;
        default:
            break;
    }

    return;
}
