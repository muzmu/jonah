# Possibly better mounter for eBPF programs
# could use C to make as ligthweight a signal handler and filter
# okay to use python for initial muont since should only be run once

from __future__ import print_function
import _thread
from bcc import BPF
import ctypes as ct
from socket import (
    inet_ntop, AF_INET, AF_INET6, __all__ as socket_all, __dict__ as socket_dct
)
import socket
from struct import pack

log = open("/home/fedora/jonah/jonah.log", "w+")

bpf_ops = BPF(src_file="bpf_progs/bpf_ops.c")

execve_fnname = bpf_ops.get_syscall_fnname("execve")
bpf_ops.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
bpf_ops.attach_kprobe(event="vfs_read",   fn_name="do_read")
bpf_ops.attach_kprobe(event="vfs_write",  fn_name="do_write")
bpf_ops.attach_kprobe(event="vfs_open",   fn_name="do_open")
bpf_ops.attach_kprobe(event="vfs_create", fn_name="do_create")


bpf_ops.attach_kprobe(event="tcp_v4_connect", fn_name="do_tcpv4")
#bpf_ops.attach_kretprobe(event="tcp_v4_disconnect", fn_name="do_tcpv4")
bpf_ops.attach_kprobe(event="tcp_v6_connect", fn_name="do_tcpv6")
#bpf_ops.attach_kretprobe(event="tcp_v6_disconnect", fn_name="do_tcpv6")

def log_file_event(cpu, data, size):
    event = bpf_ops["events"].event(data)
    e = "PID: %s \t OP: %s \t NAME: %s \t FILE: %s \n" % (event.pid, event.str.decode(
        'utf-8', 'replace'), event.comm.decode('utf-8', 'replace'), event.filename.decode('utf-8', 'replace'))#, event.path_dir.decode('utf-8', 'replace'))
    print(e)
    #log.write(e)
    #log.flush()

def log_execv_event(cpu, data, size):
    event = bpf_ops["execv_events"].event(data)
    e = "PID: %s \t NAME: %s \n" % (event.pid, event.comm.decode('utf-8', 'replace'))#, event.path_dir.decode('utf-8', 'replace'))
    print(e)
    #log.write(e)
    #log.flush()


def log_tcpv4_event(cpu, data, size):
    event = bpf_ops["tcpv4_events"].event(data)
    e = "PID: %d \t OP: %s \t NAME: %s \t ADDR: %-39s \n" % (event.pid, event.op.decode(
        'utf-8', 'replace'), event.comm.decode('utf-8', 'replace'), inet_ntop(AF_INET, pack("I", event.addr)).encode())
    print(e)
    #log.write(e)
    #log.flush()

def log_tcpv6_event(cpu, data, size):
    event = bpf_ops["tcpv6_events"].event(data)
    e = "PID: %d \t OP: %s \t NAME: %s \t ADDR: %d \n" % (event.pid, event.op.decode(
        'utf-8', 'replace'), event.comm.decode('utf-8', 'replace'), event.addr)
    print(e)
    #log.write(e)
    #log.flush()

bpf_ops["events"].open_perf_buffer(log_file_event)
bpf_ops["tcpv4_events"].open_perf_buffer(log_tcpv4_event)
bpf_ops["tcpv6_events"].open_perf_buffer(log_tcpv4_event)
bpf_ops["execv_events"].open_perf_buffer(log_execv_event)

def log_thread():
    while True:
        bpf_ops.perf_buffer_poll()

_thread.start_new_thread(log_thread, ())

print("STARTING DOCKER\n")
while True:
    try:
        pass
    except KeyboardInterrupt:
        exit()
