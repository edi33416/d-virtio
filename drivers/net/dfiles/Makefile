CC=ldc2
CFLAGS=-betterC -c
ext=.o_shipped
CC_PATH=~/dlang/ldc-1.14.0/activate
SHELL := /bin/bash
SRC=$(wildcard *.d)
TAR=$(SRC:.d=.o_shipped)

all: build

build: $(TAR) copy

%.o_shipped: %.d
	source $(CC_PATH) && $(CC) $(CFLAGS) $< -of=$@

copy:
	mv $(TAR) ..

print:
	echo $(TAR)

clean:
	cd .. ; rm -f $(TAR)


