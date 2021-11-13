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

#define PATH_LEN 256

BPF_PERF_OUTPUT(tcpv4_events);
BPF_PERF_OUTPUT(tcpv6_events);
BPF_PERF_OUTPUT(events);

BPF_ARRAY(filter_arr, u32, 1);

struct data_file
{
	u32 pid;
	char str[8];
	char comm[TASK_COMM_LEN];
	char filename[DNAME_INLINE_LEN];
	//char path_dir[PATH_LEN];
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
	return (filename[0] == 'd' && filename[1] == 'o' && filename[2] == 'c' && filename[3] == 'k' && filename[4] == 'e' && filename[5] == 'r' && filename[6] == 'd');
}

static int is_filter_pid(u32 pid)
{
	u32 key = 0, *val, fpid;
	val = filter_arr.lookup(&key);
	if (!val)
		return -1;
	fpid = *val;
	if (fpid != pid)
		return 0;
	return 1;
}

static void register_filter_pid(u32 pid)
{
	u32 key = 0, *val;
	val = filter_arr.lookup(&key);
	if (val)
		*val = pid;
}

int do_read(struct pt_regs *ctx, struct file *file)
{
	struct data_file data = {};
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	u32 pid;
	if (!PT_REGS_RC(ctx))
		return 0;

	struct dentry *de = file->f_path.dentry;
	int mode = file->f_inode->i_mode;
	struct qstr d_name = de->d_name;
	bpf_probe_read_kernel(&data.filename, sizeof(data.filename), d_name.name);

	pid = bpf_get_current_pid_tgid() >> 32;
	data.pid = pid;

	strcpy(data.str, "read");

	bpf_get_current_comm(&(data.comm), sizeof(data.comm));

	if (is_filter_proc(data.comm) && is_filter_pid(pid) < 0)
	{
		register_filter_pid(pid);
		//dentry_path_raw(de, data.path_dir, PATH_LEN);
	}

	if (is_filter_pid(pid) || is_filter_pid(t->real_parent->pid))
		events.perf_submit(ctx, &data, sizeof(data));

	return 0;
}

int do_write(struct pt_regs *ctx, struct file *file)
{
	struct data_file data = {};
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	u32 pid;
	if (!PT_REGS_RC(ctx))
		return 0;

	struct dentry *de = file->f_path.dentry;
	int mode = file->f_inode->i_mode;
	struct qstr d_name = de->d_name;
	bpf_probe_read_kernel(&data.filename, sizeof(data.filename), d_name.name);

	pid = bpf_get_current_pid_tgid() >> 32;
	data.pid = pid;

	strcpy(data.str, "write");

	bpf_get_current_comm(&(data.comm), sizeof(data.comm));

	if (is_filter_proc(data.comm) && is_filter_pid(pid) < 0)
		register_filter_pid(pid);

	if (is_filter_pid(pid) || is_filter_pid(t->real_parent->pid))
		events.perf_submit(ctx, &data, sizeof(data));

	return 0;
}

int do_open(struct pt_regs *ctx, struct file *file)
{
	struct data_file data = {};
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	u32 pid;
	if (!PT_REGS_RC(ctx))
		return 0;

	struct dentry *de = file->f_path.dentry;
	int mode = file->f_inode->i_mode;
	struct qstr d_name = de->d_name;
	bpf_probe_read_kernel(&data.filename, sizeof(data.filename), d_name.name);

	pid = bpf_get_current_pid_tgid() >> 32;
	data.pid = pid;

	strcpy(data.str, "open");

	bpf_get_current_comm(&(data.comm), sizeof(data.comm));

	if (is_filter_proc(data.comm) && is_filter_pid(pid) < 0)
		register_filter_pid(pid);

	if (is_filter_pid(pid) || is_filter_pid(t->real_parent->pid))
		events.perf_submit(ctx, &data, sizeof(data));

	return 0;
}

int do_create(struct pt_regs *ctx, struct file *file)
{
	struct data_file data = {};
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	u32 pid;
	if (!PT_REGS_RC(ctx))
		return 0;

	struct dentry *de = file->f_path.dentry;
	int mode = file->f_inode->i_mode;
	struct qstr d_name = de->d_name;
	bpf_probe_read_kernel(&data.filename, sizeof(data.filename), d_name.name);

	pid = bpf_get_current_pid_tgid() >> 32;
	data.pid = pid;

	strcpy(data.str, "create");

	bpf_get_current_comm(&(data.comm), sizeof(data.comm));

	if (is_filter_proc(data.comm) && is_filter_pid(pid) < 0)
		register_filter_pid(pid);

	if (is_filter_pid(pid) || is_filter_pid(t->real_parent->pid))
		events.perf_submit(ctx, &data, sizeof(data));

	return 0;
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

	if (is_filter_pid(pid) || is_filter_pid(t->real_parent->pid))
		tcpv4_events.perf_submit(ctx, &data, sizeof(data));

	return 0;
}

int do_tcpv6(struct pt_regs *ctx, struct sock *sk)
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

	if (is_filter_pid(pid) || is_filter_pid(t->real_parent->pid))
		tcpv6_events.perf_submit(ctx, &data, sizeof(data));

	return 0;
}