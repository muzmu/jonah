PROBE = 'tracepoint:syscalls:sys_enter_openat { printf("%s accessed by %s\n", str(args->filename), comm); }'
OUTFILE = trace.out

all:
	@echo monitoring file accesses
	@bpftrace -e $(PROBE) > $(OUTFILE)
