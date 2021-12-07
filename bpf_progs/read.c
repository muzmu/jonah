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
#define TGT_PID 615852
#define ARGSIZE  128
#define MAXARG 20
BPF_PERF_OUTPUT(read);

BPF_ARRAY(filter_arr, u32, 1);


struct data_file
{
	u32 pid;
	char str[8];
	char comm[TASK_COMM_LEN];
	char filename[DNAME_INLINE_LEN];
	//char path_dir[PATH_LEN];
};

struct val_t {
	u64 reads;
	u64 writes;
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
BPF_HASH(counts,struct data_file,struct val_t);

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
	pid = (u32)(TGT_PID);
	filter_arr.update(&key, &pid);
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
	if (d_name.len == 0 || !S_ISREG(mode)){
		return 0;
	}
	bpf_probe_read_kernel(&data.filename, sizeof(data.filename), d_name.name);

	pid = bpf_get_current_pid_tgid() >>32;
	data.pid = pid;

	strcpy(data.str, "read");

	bpf_get_current_comm(&(data.comm), sizeof(data.comm));

	if (is_filter_proc(data.comm) && is_filter_pid(pid) < 0){
		register_filter_pid(pid);
	}

	if (1 || is_filter_pid_parent_any_level(t) == 1){
		 struct val_t *valp, zero = {};
		 valp = counts.lookup_or_try_init(&data, &zero);
		 if(valp){
		 
		 	valp->reads++;
		 }
		 //read.perf_submit(ctx, &data, sizeof(data));
	}

	return 0;
}

