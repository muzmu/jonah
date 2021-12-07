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
from subprocess import check_output
argv = defaultdict(list)

def replace_line(file_name, line_num, text):
    lines = open(file_name, 'r').readlines()
    lines[line_num] = text
    out = open(file_name, 'w')
    out.writelines(lines)
    out.close()

tgt_pid = int(check_output(["pidof","dockerd"]))
repl_ln = "#define TGT_PID " + str(tgt_pid) + "\n"
replace_line("bpf_progs/execv.c", 15, repl_ln)
replace_line("bpf_progs/tcp4.c", 15, repl_ln)
replace_line("bpf_progs/tcp6.c", 15, repl_ln)
replace_line("bpf_progs/read.c", 15, repl_ln)
replace_line("bpf_progs/write.c", 15, repl_ln)

log = open("/jonah/jonah.log", "w+")

global last_pid
last_pid=-1
argv[-1].append(1)

execv_ops = BPF(src_file="bpf_progs/execv.c")
tcp4 = BPF(src_file="bpf_progs/tcp4.c")
tcp6 = BPF(src_file="bpf_progs/tcp6.c")
read = BPF(src_file="bpf_progs/read.c")
write = BPF(src_file="bpf_progs/write.c")

execve_fnname = execv_ops.get_syscall_fnname("execve")
execv_ops.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
read.attach_kprobe(event="vfs_read",   fn_name="do_read")
write.attach_kprobe(event="vfs_write",  fn_name="do_write")

tcp4.attach_kprobe(event="tcp_v4_connect", fn_name="do_tcpv4")
tcp4.attach_kretprobe(event="tcp_v4_connect", fn_name="do_tcpv4_ret")
tcp6.attach_kretprobe(event="tcp_v6_connect", fn_name="do_tcpv6")

write_file_dict = defaultdict(list);
read_file_dict = defaultdict(list);
tcp4_dict = defaultdict(list);
tcp6_dict = defaultdict(list);

def log_read_event(cpu,data,size):
    event = read["read"].event(data)
    filename = str(event.filename.decode('utf-8', 'replace'))
    event_type = str(event.str.decode('utf-8', 'replace'))
    pid = int(event.pid)
    
    read_file_dict[pid].append(filename)
    e = "PID: %s \t OP: %s \t NAME: %s \t FILE: %s \n" % (event.pid, event.str.decode(
        'utf-8', 'replace'), event.comm.decode('utf-8', 'replace'), event.filename.decode('utf-8', 'replace'))#, event.path_dir.decode('utf-8', 'replace'))
    log.write(e)
    log.flush()


def log_write_event(cpu,data,size):
    event = write["write"].event(data)
    filename = str(event.filename.decode('utf-8', 'replace'))
    event_type = str(event.str.decode('utf-8', 'replace'))
    pid = int(event.pid)
    #print(event_type,filename)
    write_file_dict[pid].append(filename)
    e = "PID: %s \t OP: %s \t NAME: %s \t FILE: %s \n" % (event.pid, event.str.decode(
        'utf-8', 'replace'), event.comm.decode('utf-8', 'replace'), event.filename.decode('utf-8', 'replace'))#, event.path_dir.decode('utf-8', 'replace'))
    log.write(e)
    log.flush()

def log_execv_event(cpu, data, size):
    event = execv_ops["execv_events"].event(data)
    argv[event.pid].append(event.argv.decode('utf-8','replace'))
    if argv[-1][0] != event.pid and argv[-1][0] != -1:
        #write logs
        #print(argv[argv[-1][0]])
    

        e = "PID: %d \t NAME: %s \n" % (argv[-1][0],str(argv[argv[-1][0]]))
    #print(e)
        argv[-1][0]=event.pid
        log.write(e)
        log.flush()

def log_tcpv4_event(cpu, data, size):
    event = tcp4["tcpv4_events"].event(data)
    e = "PID: %d \t OP: %s \t NAME: %s \t ADDR: %s \n" % (event.pid, event.op.decode(
        'utf-8', 'replace'), event.comm.decode('utf-8', 'replace').encode(), inet_ntop(AF_INET, pack("I", event.daddr)))
    tcp4_dict[event.pid].append(inet_ntop(AF_INET, pack("I", event.daddr)).encode())
    log.write(e)
    log.flush()

def log_tcpv6_event(cpu, data, size):
    event = tcp6["tcpv6_events"].event(data)
    tcp6_dict[event.pid].append(inet_ntop(AF_INET, pack("I", event.addr)).encode())
    e = "PID: %d \t OP: %s \t NAME: %s \t ADDR: %d \n" % (event.pid, event.op.decode(
        'utf-8', 'replace'), event.comm.decode('utf-8', 'replace'), event.addr)
    log.write(e)
    log.flush()

def log_cmdline(cpu,data,size):
    event=bpf_ops["cmd"].event(data)

read["read"].open_perf_buffer(log_read_event)
write["write"].open_perf_buffer(log_write_event)
tcp4["tcpv4_events"].open_perf_buffer(log_tcpv4_event)
tcp6["tcpv6_events"].open_perf_buffer(log_tcpv6_event)
execv_ops["execv_events"].open_perf_buffer(log_execv_event)

def log_read_ops_thread():
    while True:
        read.perf_buffer_poll()

def log_write_ops_thread():
    while True:
        write.perf_buffer_poll()

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
file_len = sum(1 for line in log)
while True:
    try:
	pass
    except KeyboardInterrupt:
        exit()
