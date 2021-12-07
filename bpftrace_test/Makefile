PROBE = jonah1.bt 
OUTFILE = jonah.log

all:
	@echo starting jonah...
	@bpftrace $(PROBE) > $(OUTFILE)

ready:
	dnf install bpftrace
