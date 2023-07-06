CC = gcc
CFLAGS = -Wall
LDFLAGS = -lelftool -lcapstone -lelf
INCLUDE_PATH = ./inc
OBJS = util.o command.o vmmap.o disasm-tool.o tracee.o sdb.o
PROG = sdb

all: $(OBJS)
	$(CC) $^ -L. $(LDFLAGS) -I $(INCLUDE_PATH) -o $(PROG)

%.o: %.c
	$(CC) -c $< $(CFLAGS) -o $@

.PHONY: clean
clean:
	rm -rf $(OBJS) $(PROG)
