SDB
===

simple C debugger like gdb

### How can I do with SDB ?
support basic debugger usage, like set/delete breakpoint, step by step run instruction, and dump memory content, etc.

## Getting started
### Compile
```bash
# install dependencies
sudo apt-get update
sudo apt-get install libelf-dev
./setup.sh # install capstone from source code

# compile the debugger
make
```

### Run the debugger
```bash
# start debugger only
./sdb

# start debugger and load the debug target
./sdb <program_path>
```

## Commands

#### load *path/to/a/program*
load a program to the debugger

#### start
start the program and stop at the first

#### run
run the program

#### break *address*
add a break point at *address*

#### delete *breakpoint-id*
delete a break point by id, which you can get the breakpoint id by **list** commands

#### list
list break points and their ids

#### cont
continue running your program

#### si
Execute one instruction

#### disasm *address*
disassemble instructions in a file or a memory region

#### dump *address* *length*
dump memory content start from *address* and dump *length*

#### vmmap
show memory layout

#### getregs
get the valus of all registers

all supported register is listed as following
- rax, rbx, rcx, rdx, rbp, rsi, rdi, rip, rsp, eflags
- r8 ~ r15

#### get *reg*
get a single value from a register

#### set *reg* *val*
set specific value to a register

#### help
show the help message

#### exit
terminate the debugger

## Example
```
TODO...
```

## License
MIT
