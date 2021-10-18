#include <linux/sched.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/string.h>

BPF_PERF_OUTPUT(events);

struct data_t {
	u32 pid;
	char str[8];
	char comm[TASK_COMM_LEN];
	char filename[TASK_COMM_LEN];
};


int do_read(struct pt_regs *ctx){
	struct data_t data = {};
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	struct path *p = &(t->fs->pwd);

	u32 pid;
    if (!PT_REGS_RC(ctx))
    	return 0;
    
	pid = bpf_get_current_pid_tgid() >> 32;
    data.pid = pid;

	strcpy(data.str, "read");
	int i = 0;
	for(i; i < TASK_COMM_LEN; i++){
		data.filename[i] = (p->dentry->d_name.name)[i];
		if((p->dentry->d_iname)[i+1] == '\0')
			break;
	}
	//strcpy(data.filename, (char*)(p->dentry->d_iname));
	//sprintf(data.filename, "%lu", p->dentry->d_time);

	bpf_get_current_comm(&(data.comm), sizeof(data.comm));
	
	events.perf_submit(ctx, &data, sizeof(data));

	return 0;
}

int do_write(struct pt_regs *ctx){
	struct data_t data = {};
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	struct path *p = &(t->fs->pwd);
	u32 pid;
    if (!PT_REGS_RC(ctx))
    	return 0;
    
	pid = bpf_get_current_pid_tgid() >> 32;
    data.pid = pid;

	strcpy(data.str, "write");
	int i = 0;
	for(i; i < TASK_COMM_LEN; i++){
		data.filename[i] = (p->dentry->d_name.name)[i];
		if((p->dentry->d_iname)[i+1] == '\0')
			break;
	}

	bpf_get_current_comm(&(data.comm), sizeof(data.comm));
	events.perf_submit(ctx, &data, sizeof(data));

	return 0;
}

int do_open(struct pt_regs *ctx){
	struct data_t data = {};
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	struct path *p = &(t->fs->pwd);
	u32 pid;
    if (!PT_REGS_RC(ctx))
    	return 0;
    
	pid = bpf_get_current_pid_tgid() >> 32;
    data.pid = pid;

	strcpy(data.str, "open");
	int i = 0;
	for(i; i < TASK_COMM_LEN; i++){
		data.filename[i] = (p->dentry->d_name.name)[i];
		if((p->dentry->d_iname)[i+1] == '\0')
			break;
	}

	bpf_get_current_comm(&(data.comm), sizeof(data.comm));
	events.perf_submit(ctx, &data, sizeof(data));

	return 0;
}

int do_create(struct pt_regs *ctx){
	struct data_t data = {};
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	struct path *p = &(t->fs->pwd);
	u32 pid;
    if (!PT_REGS_RC(ctx))
    	return 0;
    
	pid = bpf_get_current_pid_tgid() >> 32;
    data.pid = pid;

	strcpy(data.str, "create");
	int i = 0;
	for(i; i < TASK_COMM_LEN; i++){
		data.filename[i] = (p->dentry->d_name.name)[i];
		if((p->dentry->d_iname)[i+1] == '\0')
			break;
	}

	bpf_get_current_comm(&(data.comm), sizeof(data.comm));
	events.perf_submit(ctx, &data, sizeof(data));

	return 0;
}