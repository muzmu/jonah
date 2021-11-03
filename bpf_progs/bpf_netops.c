#include <linux/bpf.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <bcc/proto.h>

#define IP_TCP 6
#define IP_UDP 17
#define IP_ICMP 1
#define ETH_HLEN 14


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
/*
struct socket_info{
	u32 saddr, daddr;
	u32 pid;
	char comm[TASK_COMM_LEN];
};
*/
struct data_t {
	u32 pid;
	u32 addr;
	char op[10];
	char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(tcpv4_events);
BPF_PERF_OUTPUT(tcpv6_events);
BPF_PERF_OUTPUT(raw_events);
/*
int packet_monitor(struct pt_regs *ctx,struct __sk_buff *skb){
	struct socket_info sock = {};
	u8 *cursor = 0;
	long *count = 0;
	long one=1;
	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
	if (ip->nextp != IP_TCP) 
	{
		if (ip -> nextp != IP_UDP) 
		{
			if (ip -> nextp != IP_ICMP) 
				return 0; 
		}
	}
	
	//sock.pid = bpf_get_current_pid_tgid();
//	u32 pid;
//	sock.pid = bpf_get_current_pid_tgid() >> 32;
//	sock.pid = pid;

sock.saddr = ip -> src;

	//bpf_get_current_comm(&(sock.comm), sizeof(sock.comm));
	sock.daddr = ip -> dst;
	raw_events.perf_submit(ctx, &sock ,sizeof(sock));	
	return 0;
}
*/
int do_tcpv4(struct pt_regs *ctx, struct sock *sk){
	struct data_t data = {};
	struct sock *skp = sk;
	struct inet_sock *sockp = (struct inet_sock *)skp;
	u32 saddr = 0;
	bpf_probe_read_kernel(&saddr, sizeof(saddr), &sockp->inet_saddr);

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
	struct sock *skp = sk;
	struct inet_sock *sockp = (struct inet_sock *)skp;
	u32 saddr = 0;
	bpf_probe_read_kernel(&saddr, sizeof(saddr), &sockp->inet_saddr);

	u32 pid;
	pid = bpf_get_current_pid_tgid() >> 32;
	data.pid = pid;

	strcpy(data.op, "TCP IPv4");
	data.addr = saddr;
	bpf_get_current_comm(&(data.comm), sizeof(data.comm));

	tcpv6_events.perf_submit(ctx, &data, sizeof(data));

	return 0;
}

int raw_monitor(struct __sk_buff *skb){

	return -1;
}
