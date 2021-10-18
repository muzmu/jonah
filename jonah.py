# Possibly better mounter for eBPF programs
# could use C to make as ligthweight a signal handler and filter
# okay to use python for initial muont since should only be run once

from __future__ import print_function

from bcc import BPF
from bcc.utils import printb

#print("jonah: prepping log file")
log = open("jonah.log", "w+")

#print("jonah: mounting programs\n")
trigger_prog = "" #"docker"

bpf_netops = BPF(src_file="bpf_progs/bpf_netops.c")
bpf_fileops = BPF(src_file="bpf_progs/bpf_fileops.c")

bpf_fileops.attach_kprobe(event="vfs_read",   fn_name="do_read")
bpf_fileops.attach_kprobe(event="vfs_write",  fn_name="do_write")
bpf_fileops.attach_kprobe(event="vfs_open",   fn_name="do_open")
bpf_fileops.attach_kprobe(event="vfs_create", fn_name="do_create")

bpf_netops.attach_kprobe(event="tcp_v4_connect", fn_name="do_tcpv4")
bpf_netops.attach_kretprobe(event="tcp_v4_connect", fn_name="do_tcpv4")
bpf_netops.attach_kprobe(event="tcp_v6_connect", fn_name="do_tcpv6")
bpf_netops.attach_kretprobe(event="tcp_v6_connect", fn_name="do_tcpv6")

def log_file_event(cpu, data, size):
    event = bpf_fileops["events"].event(data)
    if event.comm.decode('utf-8', 'replace') != trigger_prog:
        e = "PID: %d \t OP: %s \t NAME: %s \t FILE: %s \n" % (event.pid, event.str.decode('utf-8', 'replace'), event.comm.decode('utf-8', 'replace'), event.filename.decode('utf-8', 'replace'))
        #print(e)
        log.write(e)

def log_tcpv4_event(cpu, data, size):
    event = bpf_netops["tcpv4_events"].event(data)
    if event.comm.decode('utf-8', 'replace') != trigger_prog:
        e = "PID: %d \t OP: %s \t NAME: %s \t ADDR: %d \n" % (event.pid, event.op.decode('utf-8', 'replace'), event.comm.decode('utf-8', 'replace'), event.addr)
        #print(e)
        log.write(e)

def log_tcpv6_event(cpu, data, size):
    event = bpf_netops["tcpv6_events"].event(data)
    if event.comm.decode('utf-8', 'replace') != trigger_prog:
        e = "PID: %d \t OP: %s \t NAME: %s \t ADDR: %d \n" % (event.pid, event.op.decode('utf-8', 'replace'), event.comm.decode('utf-8', 'replace'), event.addr)
        #print(e)
        log.write(e)

#bpf_fileops["events"].open_perf_buffer(log_file_event)
bpf_netops["tcpv4_events"].open_perf_buffer(log_tcpv4_event)
bpf_netops["tcpv6_events"].open_perf_buffer(log_tcpv4_event)

while True:
    try:
        #bpf_fileops.perf_buffer_poll()
        bpf_netops.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()