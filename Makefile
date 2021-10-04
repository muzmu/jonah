PROBE = basic_prog.bt 
OUTFILE = accesses.log

all:
	@echo monitoring file accesses
	@bpftrace $(PROBE) > $(OUTFILE)

ready:
	dnf install bpftrace
