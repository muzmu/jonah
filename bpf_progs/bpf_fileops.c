#include <linux/sched.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_PERF_OUTPUT(events);
BPF_ARRAY(filter_arr, u32, 1);

struct data_t {
	u32 pid;
	char str[8];
	char comm[TASK_COMM_LEN];
	char filename[DNAME_INLINE_LEN];
};

static int is_filter_file(char filename[]){
	return (filename[0]=='D' && filename[1] == 'o' && filename[2] == 'c' 
	&& filename[3] == 'k' && filename[4] == 'e' && filename[5] == 'r' 
	&& filename[6] == 'f' && filename[7] == 'i' && filename[8] == 'l'
	&& filename[9] == 'e');
}

static int is_filter_pid(u32 pid){
	u32 key = 0, *val, fpid;
	val = filter_arr.lookup(&key);
	if(!val)
		return -1;
	fpid = *val;
	if(fpid != pid)
		return 0;
	return 1;
}

static void register_filter_pid(u32 pid){
	u32 key = 0, *val;
	val = filter_arr.lookup(&key);
	if(val)
		*val = pid;
}

int do_read(struct pt_regs *ctx,struct file *file){
	struct data_t data = {};
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	struct path *p = &(t->fs->pwd);
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

	if(is_filter_file(data.filename) && is_filter_pid(pid) < 0)
		register_filter_pid(pid);
	
	if(is_filter_pid(pid) || is_filter_pid(t->real_parent->pid))
		events.perf_submit(ctx, &data, sizeof(data));

	return 0;
}
/*
int do_write(struct pt_regs *ctx,struct file *file){
	struct data_t data = {};
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	struct path *p = &(t->fs->pwd);
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
	
	if(strncmp(data.comm, "docker", 6) == 0 && is_filter_pid(pid) < 0)
		register_filter_pid(pid);
	
	if(is_filter_pid(pid) || is_filter_pid(t->real_parent->pid))
		events.perf_submit(ctx, &data, sizeof(data));

	return 0;
}

int do_open(struct pt_regs *ctx,struct file *file){
	struct data_t data = {};
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	struct path *p = &(t->fs->pwd);
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
	
	if(strncmp(data.comm, "docker", 6) == 0 && is_filter_pid(pid) < 0)
		register_filter_pid(pid);
	
	if(is_filter_pid(pid) || is_filter_pid(t->real_parent->pid))
		events.perf_submit(ctx, &data, sizeof(data));

	return 0;
}

int do_create(struct pt_regs *ctx,struct file *file){
	struct data_t data = {};
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	struct path *p = &(t->fs->pwd);
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
	
	if(strncmp(data.comm, "docker", 6) == 0 && is_filter_pid(pid) < 0)
		register_filter_pid(pid);
	
	if(is_filter_pid(pid) || is_filter_pid(t->real_parent->pid))
		events.perf_submit(ctx, &data, sizeof(data));

	return 0;
}*/
