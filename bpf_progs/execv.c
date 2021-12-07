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
BPF_PERF_OUTPUT(execv_events);

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
	}

	if (1 || is_filter_pid_parent_any_level(task) == 1){
		// Some kernels, like Ubuntu 4.13.0-generic, return 0
		// as the real_parent->tgid.
		// We use the get_ppid function as a fallback in those cases. (#1883)
		data.ppid = task->real_parent->tgid;
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

