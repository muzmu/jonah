#include <linux/sched.h>
#include <linux/string.h>
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <bcc/proto.h>

struct tcp_ipv4_event_t {
    u64 ts_ns;
    u32 type;
    u32 pid;
    char comm[TASK_COMM_LEN];
    u8 ip;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 netns;
};

struct tcp_ipv6_event_t {
    u64 ts_ns;
    u32 type;
    u32 pid;
    char comm[TASK_COMM_LEN];
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 sport;
    u16 dport;
    u32 netns;
    u8 ip;
};

struct data_t {
    u32 pid;
    u32 addr;
    char op[10];
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(tcpv4_events);
BPF_PERF_OUTPUT(tcpv6_events);

int do_tcpv4(struct pt_regs *ctx, struct sock *sk){
    struct data_t data = {};
    u32 saddr = sk->__sk_common.skc_rcv_saddr;
    u32 pid;
    pid = bpf_get_current_pid_tgid() >> 32;
    data.pid = pid;

    strcpy(data.op, "TCP IPv4");
    data.addr = saddr;
    bpf_get_current_comm(&(data.comm), sizeof(data.comm));

    tcpv4_events.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}

int do_tcpv6(struct pt_regs *ctx, struct sock *sk){
    struct data_t data = {};
    u32 saddr = sk->__sk_common.skc_daddr;
    u32 pid;
    pid = bpf_get_current_pid_tgid() >> 32;
    data.pid = pid;

    strcpy(data.op, "TCP IPv6");
    data.addr = saddr;
    bpf_get_current_comm(&(data.comm), sizeof(data.comm));

    tcpv4_events.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}