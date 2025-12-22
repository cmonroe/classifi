# Development Makefile for building outside OpenWrt
# This is for testing purposes only

CC ?= gcc
CLANG ?= clang
BPFTOOL ?= bpftool

CFLAGS := -Wall -O2 -g
LDFLAGS := -lbpf -lelf -lz -lndpi

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86
BPF_INCLUDE := -I/usr/include/bpf

TARGETS := classifi classifi.bpf.o

.PHONY: all clean

all: $(TARGETS)

classifi.bpf.o: classifi.bpf.c classifi_common.h
	$(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDE) -c $< -o $@

classifi: classifi.c classifi_common.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)

install: all
	install -D -m 0755 classifi $(DESTDIR)/usr/sbin/classifi
	install -D -m 0644 classifi.bpf.o $(DESTDIR)/usr/lib/bpf/classifi.bpf.o

.DEFAULT_GOAL := all
