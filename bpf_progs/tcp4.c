#include <linux/bpf.h>
#include <linux/sched.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <bcc/proto.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define PATH_LEN 256

#define ARGSIZE  128
#define MAXARG 20
BPF_PERF_OUTPUT(tcpv4_events);

BPF_ARRAY(filter_arr, u32, 1);

struct data_file
{
	u32 pid;
	char str[8];
	char comm[TASK_COMM_LEN];
	char filename[DNAME_INLINE_LEN];
	//char path_dir[PATH_LEN];
};

struct str_t {
	u64 pid;
	char str[80];
};

enum event_type {
	EVENT_ARG,
	EVENT_RET,
};

struct data_t {
	u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
	u32 ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
	u32 uid;
	char comm[TASK_COMM_LEN];
	enum event_type type;
	char argv[ARGSIZE];
	int retval;
};

struct data_net
{
	u32 pid;
	u32 addr;
	char op[10];
	char comm[TASK_COMM_LEN];
};

static int is_filter_proc(char filename[])
{
	return (filename[0] == 'd' && filename[1] == 'o' && filename[2] == 'c' && filename[3] == 'k' 
			&& filename[4] == 'e' && filename[5] == 'r' && filename[6] == 'd');
}

static int is_filter_pid(u32 pid)
{
	u32 key = 0, *val, fpid;
	val = filter_arr.lookup(&key);
	if (!val || *val == 0){
		return -1;
	}
	fpid = *val;
	if (fpid == pid){
		return 1;
	}
	return 0;
}

static int is_filter_pid_parent_any_level(struct task_struct *t){
	u32 key = 0, *val, fpid,pid;
	val = filter_arr.lookup(&key);
	pid = t->tgid;
	if (!val || *val == 0){
		return -1;
	}
	fpid = *val;
	int i;
	for(i = 0; i < 10; i++) {
		if (fpid == pid){
			return 1;
		}

		t=t->real_parent;
		pid = t->tgid;
		if(pid == 1)
			break;
	}

	return 0;
}

static void register_filter_pid(u32 pid)
{
	u32 key = 0;
	filter_arr.update(&key, &pid);
}
int do_tcpv4(struct pt_regs *ctx, struct sock *sk)
{
	struct data_net data = {};
	struct sock *skp = sk;
	struct inet_sock *sockp = (struct inet_sock *)skp;
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();

	u32 saddr = 0;
	bpf_probe_read_kernel(&saddr, sizeof(saddr), &sockp->inet_saddr);

	u32 pid;
	pid = bpf_get_current_pid_tgid() >> 32;
	data.pid = pid;

	strcpy(data.op, "TCP IPv4");
	data.addr = saddr;
	bpf_get_current_comm(&(data.comm), sizeof(data.comm));

	if (is_filter_proc(data.comm) && is_filter_pid(pid) < 0)
		register_filter_pid(pid);

	if (1 || is_filter_pid_parent_any_level(t) == 1)
		tcpv4_events.perf_submit(ctx, &data, sizeof(data));

	return 0;
}
