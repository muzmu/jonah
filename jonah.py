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
from collections import defaultdict
import time
argv = defaultdict(list)

log = open("/home/fedora/muz/jonah/jonah.log", "w+")

#bpf_ops = BPF(src_file="bpf_progs/bpf_ops.c")
execv_ops = BPF(src_file="bpf_progs/execv.c")
tcp4 = BPF(src_file="bpf_progs/tcp4.c")
tcp6 = BPF(src_file="bpf_progs/tcp6.c")
read= BPF(src_file="bpf_progs/read.c")
write= BPF(src_file="bpf_progs/write.c")

execve_fnname = execv_ops.get_syscall_fnname("execve")
#bpf_ops.attach_uretprobe(name='/bin/bash',sym="readline", fn_name="printret")
execv_ops.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
read.attach_kprobe(event="vfs_read",   fn_name="do_read")
write.attach_kprobe(event="vfs_write",  fn_name="do_write")
#file_ops.attach_kprobe(event="vfs_open",   fn_name="do_open")
#file_ops.attach_kprobe(event="vfs_create", fn_name="do_create")


tcp4.attach_kprobe(event="tcp_v4_connect", fn_name="do_tcpv4")
tcp6.attach_kprobe(event="tcp_v6_connect", fn_name="do_tcpv6")
#bpf_ops.attach_kretprobe(event="tcp_v6_disconnect", fn_name="do_tcpv6")
write_file_dict = defaultdict(list);
read_file_dict = defaultdict(list);
tcp4_dict = defaultdict(list);
tcp6_dict = defaultdict(list);

def log_read_event():
    time.sleep(4)
    counts = read.get_table("counts")
    #for key,value in counts.items():
     #   print(key.pid,key.filename)

    '''event = read["read"].event(data)
    filename = str(event.filename.decode('utf-8', 'replace'))
    event_type = str(event.str.decode('utf-8', 'replace'))
    pid = int(event.pid)
    try:
        f = open("/proc/"+str(pid)+"/cmdline")
        #print(f.readline())
    except:
        a=1
    #print(event_type,filename)
    
    read_file_dict[pid].append(filename)
    e = "PID: %s \t OP: %s \t NAME: %s \t FILE: %s \n" % (event.pid, event.str.decode(
        'utf-8', 'replace'), event.comm.decode('utf-8', 'replace'), event.filename.decode('utf-8', 'replace'))#, event.path_dir.decode('utf-8', 'replace'))
    #print(e)
    #log.write(e)
    #log.flush()'''


def log_write_event():
    time.sleep(4)
    counts = write.get_table("counts")
    for key,value in counts.items():
        print(key.pid,key.filename)
        
    '''event = write["write"].event(data)
    filename = str(event.filename.decode('utf-8', 'replace'))
    event_type = str(event.str.decode('utf-8', 'replace'))
    pid = int(event.pid)
    try:
        f = open("/proc/"+str(pid)+"/cmdline")
        #print(f.readline())
    except:
        a=1
    #print(event_type,filename)
    write_file_dict[pid].append(filename)
    e = "PID: %s \t OP: %s \t NAME: %s \t FILE: %s \n" % (event.pid, event.str.decode(
        'utf-8', 'replace'), event.comm.decode('utf-8', 'replace'), event.filename.decode('utf-8', 'replace'))#, event.path_dir.decode('utf-8', 'replace'))
   # print(e)
    #log.write(e)
    #log.flush()'''

def log_execv_event(cpu, data, size):
    event = execv_ops["execv_events"].event(data)
    argv[event.pid].append(event.argv)

    #print(argv)
    #e = "PID: %s \t NAME: %s " % (event.pid, event.comm.decode('utf-8', 'replace'),event.argv[0])#, event.path_dir.decode('utf-8', 'replace'))
    #print(e)
    #log.write(e)
    #log.flush()

def log_tcpv4_event(cpu, data, size):
    event = tcp4["tcpv4_events"].event(data)
    e = "PID: %d \t OP: %s \t NAME: %s \t ADDR: %-39s \n" % (event.pid, event.op.decode(
        'utf-8', 'replace'), event.comm.decode('utf-8', 'replace'), inet_ntop(AF_INET, pack("I", event.addr)).encode())
    #print(e)
    tcp4_dict[event.pid].append(inet_ntop(AF_INET, pack("I", event.addr)).encode())
   # print(tcp4_dict)
    #log.write(e)
    #log.flush()

def log_tcpv6_event(cpu, data, size):
    event = tcp6["tcpv6_events"].event(data)
    tcp6_dict[event.pid].append(inet_ntop(AF_INET, pack("I", event.addr)).encode())
    e = "PID: %d \t OP: %s \t NAME: %s \t ADDR: %d \n" % (event.pid, event.op.decode(
        'utf-8', 'replace'), event.comm.decode('utf-8', 'replace'), event.addr)
    #print(e)
    #print(tcp6_dict)
    #log.write(e)
    #log.flush()

def log_cmdline(cpu,data,size):
    event=bpf_ops["cmd"].event(data)
    #print(event.pid,event.str)

#bpf_ops["cmd"].open_perf_buffer(log_cmdline)
#read["read"].open_perf_buffer(log_read_event)
#write["write"].open_perf_buffer(log_write_event)
tcp4["tcpv4_events"].open_perf_buffer(log_tcpv4_event)
tcp6["tcpv6_events"].open_perf_buffer(log_tcpv6_event)
execv_ops["execv_events"].open_perf_buffer(log_execv_event)

def log_read_ops_thread():
    while True:
        log_read_event()


def log_write_ops_thread():
    while True:
        log_write_event()

def log_execv_ops_thread():
    while True:
        execv_ops.perf_buffer_poll()
def log_tcp4_thread():
    while True:
        tcp4.perf_buffer_poll()
def log_tcp6_thread():
    while True:
        tcp6.perf_buffer_poll()

_thread.start_new_thread(log_read_ops_thread, ())
_thread.start_new_thread(log_write_ops_thread, ())
_thread.start_new_thread(log_execv_ops_thread, ())
_thread.start_new_thread(log_tcp4_thread, ())
_thread.start_new_thread(log_tcp6_thread, ())

print("STARTING DOCKER\n")
while True:
    try:
        pass
    except KeyboardInterrupt:
        exit()
