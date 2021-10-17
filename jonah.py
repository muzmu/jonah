# Possibly better mounter for eBPF programs
# could use C to make as ligthweight a signal handler and filter
# okay to use python for initial muont since should only be run once

import sys
import time

from bcc import BPF
from bcc.utils import printb

# load BPF programs into the program

bpf_create = BPF(src_file="bpf_progs/creat_prog.c")
#bpf_mod = BPF(src_file="bpf_progs/mod_prog.c")
#bpf_net_in = BPF(src_file="bpf_progs/net_in_prog.c")
#bpf_net_out = BPF(src_file="bpf_progs/net_out_prog.c")

# attach kprobes to local file access / modification / creation methods

print("jonah: mounting programs\n")

mtpt = bpf_create.get_syscall_fnname("write")

bpf_create.attach_kprobe(event=mtpt, fn_name="creat_watch")
#bpf_mod.attach_kretprobe(event="vfs_write", fn_name="write_watch")
#bpf_mod.attach_kretprobe(event="vfs_read", fn_name="read_watch")

def register_hook(cpu, data, size):
    event = bpf_create["events"].event(data)
    printb(b"%-16s %-6d %s" %(event.comm, event.pid, b"jonah"))


bpf_create["events"].open_perf_buffer(register_hook)
#bpf_mod["events"].open_perf_buffer(register_hook)

while 1:
    try:
        bpf_create.perf_buffer_poll()
        #bpf_mod.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
