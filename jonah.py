# Possibly better mounter for eBPF programs
# could use C to make as ligthweight a signal handler and filter
# okay to use python for initial muont since should only be run once

from __future__ import print_function
import sys
import time

from bcc import BPF
from bcc.utils import printb

print("jonah: mounting programs\n")

b = BPF(src_file="bpf_progs/bpf_fileops.c")

b.attach_kprobe(event="vfs_read",   fn_name="do_read")
b.attach_kprobe(event="vfs_write",  fn_name="do_write")
b.attach_kprobe(event="vfs_open",   fn_name="do_open")
b.attach_kprobe(event="vfs_create", fn_name="do_create")

def log_event(cpu, data, size):
    event = b["events"].event(data)
    print("PROC: %d \t OP: %s" % (event.pid, event.str.decode('utf-8', 'replace')))

b["events"].open_perf_buffer(log_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()