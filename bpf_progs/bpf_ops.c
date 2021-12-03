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
BPF_PERF_OUTPUT(tcpv6_events);
BPF_PERF_OUTPUT(events);
BPF_PERF_OUTPUT(execv_events);
BPF_PERF_OUTPUT(cmd);

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

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
	bpf_probe_read_user(data->argv, sizeof(data->argv), ptr);
	execv_events.perf_submit(ctx, data, sizeof(struct data_t));
	return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
	const char *argp = NULL;
	bpf_probe_read_user(&argp, sizeof(argp), ptr);
	if (argp) {
		return __submit_arg(ctx, (void *)(argp), data);
	}
	return 0;
}

int printret(struct pt_regs *ctx) {
	struct str_t data  = {};
	char comm[TASK_COMM_LEN] = {};
	u32 pid;
	if (!PT_REGS_RC(ctx))
		return 0;
	pid = bpf_get_current_pid_tgid() >> 32;
	data.pid = pid;
	bpf_probe_read_user(&data.str, sizeof(data.str), (void *)PT_REGS_RC(ctx));
	bpf_get_current_comm(&comm, sizeof(comm));
	if (comm[0] == 'b' && comm[1] == 'a' && comm[2] == 's' && comm[3] == 'h' && comm[4] == 0 ) {
		cmd.perf_submit(ctx,&data,sizeof(data));
	}
	return 0;
};

int syscall__execve(struct pt_regs *ctx,
		const char __user *filename,
		const char __user *const __user *__argv,
		const char __user *const __user *__envp)
{
	u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
	// create data here and pass to submit_arg to save stack space (#555)
	struct data_t data = {};
	struct task_struct *task;
	data.pid = bpf_get_current_pid_tgid() >> 32;
	
	bpf_get_current_comm(&data.comm, sizeof(data.comm));
	task = (struct task_struct *)bpf_get_current_task();
	if (is_filter_proc(data.comm) && is_filter_pid(data.pid) < 0){
		register_filter_pid(data.pid);
		//events.perf_submit(ctx, &data, sizeof(data));
	}

	if (is_filter_pid_parent_any_level(task) == 1){
		// Some kernels, like Ubuntu 4.13.0-generic, return 0
		// as the real_parent->tgid.
		// We use the get_ppid function as a fallback in those cases. (#1883)
		data.ppid = task->real_parent->tgid;
		//data.type = EVENT_ARG;
		__submit_arg(ctx, (void *)filename, &data);
		// skip first arg, as we submitted filename

		for (int i = 1; i < MAXARG; i++) {
			if (submit_arg(ctx, (void *)&__argv[i], &data) == 0)
				goto out;
			}
		// handle truncated argument list
		char ellipsis[] = "...";
		__submit_arg(ctx, (void *)ellipsis, &data);
	}

out:
	return 0;
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

	pid = bpf_get_current_pid_tgid() >>32;
	data.pid = pid;

	strcpy(data.str, "read");

	bpf_get_current_comm(&(data.comm), sizeof(data.comm));

	if (is_filter_proc(data.comm) && is_filter_pid(pid) < 0){
		register_filter_pid(pid);
		//events.perf_submit(ctx, &data, sizeof(data));
	}

	if (is_filter_pid_parent_any_level(t) == 1){
		events.perf_submit(ctx, &data, sizeof(data));
	}

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

	if (is_filter_pid_parent_any_level(t) == 1){
		events.perf_submit(ctx, &data, sizeof(data));
	}
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

	if (is_filter_pid_parent_any_level(t) == 1)
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

	if (is_filter_pid_parent_any_level(t) == 1)
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

	if (is_filter_pid_parent_any_level(t) == 1)
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

	if (is_filter_pid_parent_any_level(t) == 1)
		tcpv6_events.perf_submit(ctx, &data, sizeof(data));

	return 0;
}
