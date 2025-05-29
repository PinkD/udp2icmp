.PHONY: all
all: build

.PHONY: build
build: udp2icmp

udp2icmp: ingress.skel.h egress.skel.h common.h flags.h main.h main.c
	clang -lbpf main.c -o udp2icmp

test: egress.skel.h common.h test.c
	clang -lbpf test.c -o udp2icmp-test
	sudo ./udp2icmp-test

.PHONY: generate-skeleton
generate-skeleton: ingress.skel.h egress.skel.h

ingress.skel.h: ingress.bpf.o
	bpftool gen skeleton ingress.bpf.o > ingress.skel.h

egress.skel.h: egress.bpf.o
	bpftool gen skeleton egress.bpf.o > egress.skel.h

ingress.bpf.o: ingress.bpf.c vmlinux.h common.h defs.h
	clang -DUSE_VMLINUX=1 -O2 -g -Wall -target bpf -c ingress.bpf.c -o ingress.bpf.o
	strip -g ingress.bpf.o

egress.bpf.o: egress.bpf.c vmlinux.h common.h defs.h
	clang -DUSE_VMLINUX=1 -O2 -g -Wall -target bpf -c egress.bpf.c -o egress.bpf.o
	strip -g egress.bpf.o

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: rebuild
rebuild: clean build

.PHONY: clean
clean:
	rm -f vmlinux.h
	rm -f *.o
	rm -f *.skel.h
	rm -f a.out
