PROG=ptpver20
$(PROG): $(PROG).c $(PROG).skel.h
	clang `pkg-config --cflags libbpf` -Wall -O2 -o $@ $< `pkg-config --libs libbpf`

$(PROG).skel.h: $(PROG).bpf.o
	bpftool gen skeleton $(PROG).bpf.o >$@

$(PROG).bpf.o: $(PROG).bpf.c vmlinux.h
	clang -O2 -target bpf -c $< -o $@

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c >$@

clean:
	-rm -f vmlinux.h $(PROG).bpf.o $(PROG).skel.h $(PROG)

.PHONY: clean
