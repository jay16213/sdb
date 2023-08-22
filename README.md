SDB
===

[![Develop CI](https://github.com/jay16213/sdb/actions/workflows/develop.yml/badge.svg)](https://github.com/jay16213/sdb/actions/workflows/develop.yml)

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
![example.gif](./example.gif)

```
$ ./sdb sample/hello64
** program 'sample/hello64' load. entry point: 0x4000b0, vaddr: 0x4000b0, offset: 0xb0, size: 0x23
sdb> disasm 0x4000b0
      4000b0: b8 04 00 00 00                    mov       eax, 4
      4000b5: bb 01 00 00 00                    mov       ebx, 1
      4000ba: b9 d4 00 60 00                    mov       ecx, 0x6000d4
      4000bf: ba 0e 00 00 00                    mov       edx, 0xe
      4000c4: cd 80                             int       0x80
      4000c6: b8 01 00 00 00                    mov       eax, 1
      4000cb: bb 00 00 00 00                    mov       ebx, 0
      4000d0: cd 80                             int       0x80
      4000d2: c3                                ret
sdb> b 0x4000c6
sdb> l
  0:  4000c6
sdb> run
** pid 11796
hello, world!
** breakpoint @       4000c6: b8 01 00 00 00                    mov       eax, 1
sdb> set rip 0x4000b0
sdb> cont
hello, world!
** breakpoint @       4000c6: b8 01 00 00 00                    mov       eax, 1
sdb> delete 0
** breakpoint 0 deleted.
sdb> set rip 0x4000b0
sdb> cont
hello, world!
** child process 11796 terminated normally (code 0)
```

## License
MIT
