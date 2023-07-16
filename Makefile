CC = gcc
CFLAGS = -Wall
DEBUG_FLAGS = -DDEBUG -g3 -fno-inline -O0
LDFLAGS = -lelftool -lcapstone -lelf
INCLUDE_PATH = ./inc
OBJS = util.o command.o vmmap.o disasm-tool.o tracee.o sdb.o
PROG = sdb

all: executable

debug: CFLAGS += $(DEBUG_FLAGS)
debug: executable

executable: $(OBJS)
	$(CC) $^ -L. $(LDFLAGS) -o $(PROG)

test: executable
	./test.sh

%.o: %.c
	$(CC) -I $(INCLUDE_PATH) -c $< $(CFLAGS) -o $@

.PHONY: clean
clean:
	rm -rf $(OBJS) $(PROG)
