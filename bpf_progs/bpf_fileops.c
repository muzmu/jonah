#include <linux/sched.h>

BPF_PERF_OUTPUT(events);

struct data_t {
	u32 pid;
	u32 op;
	char str[80];
};

/*
enum op_types {
	READ = 1,
	WRITE,
	OPEN,
	CREATE,
	MAXOP
};*/

int do_read(struct pt_regs *ctx){
	struct data_t data = {};
	u32 pid;
    if (!PT_REGS_RC(ctx))
    	return 0;
    
	data.op = 1;
	pid = bpf_get_current_pid_tgid() >> 32;
    data.pid = pid;
    //bpf_probe_read_user(&data.str, sizeof(data.str), (void *)PT_REGS_RC(ctx));
	data.str[0]='r';
	data.str[1]='e';
	data.str[2]='a';
	data.str[3]='d';
	data.str[4]= 0;
	events.perf_submit(ctx, &data, sizeof(data));

	return 0;
}

int do_write(struct pt_regs *ctx){
	struct data_t data = {};
	u32 pid;
    if (!PT_REGS_RC(ctx))
    	return 0;
    
	data.op = 1;
	pid = bpf_get_current_pid_tgid() >> 32;
    data.pid = pid;
    //bpf_probe_read_user(&data.str, sizeof(data.str), (void *)PT_REGS_RC(ctx));
	data.str[0]='w';
	data.str[1]='r';
	data.str[2]='i';
	data.str[3]='t';
	data.str[4]='e';
	data.str[5]= 0;	
	events.perf_submit(ctx, &data, sizeof(data));

	return 0;
}

int do_open(struct pt_regs *ctx){
	struct data_t data = {};
	u32 pid;
    if (!PT_REGS_RC(ctx))
    	return 0;
    
	data.op = 1;
	pid = bpf_get_current_pid_tgid() >> 32;
    data.pid = pid;
    //bpf_probe_read_user(&data.str, sizeof(data.str), (void *)PT_REGS_RC(ctx));
	data.str[0]='o';
	data.str[1]='p';
	data.str[2]='e';
	data.str[3]='n';
	data.str[4]= 0;
	events.perf_submit(ctx, &data, sizeof(data));

	return 0;
}

int do_create(struct pt_regs *ctx){
	struct data_t data = {};
	u32 pid;
    if (!PT_REGS_RC(ctx))
    	return 0;
    
	data.op = 1;
	pid = bpf_get_current_pid_tgid() >> 32;
    data.pid = pid;
    //bpf_probe_read_user(&data.str, sizeof(data.str), (void *)PT_REGS_RC(ctx));
	data.str[0]='c';
	data.str[1]='r';
	data.str[2]='e';
	data.str[3]='a';
	data.str[4]='t';
	data.str[5]='e';
	data.str[6]= 0;
	events.perf_submit(ctx, &data, sizeof(data));

	return 0;
}