#include <linux/sched.h>

BPF_PERF_OUTPUT(events);

struct data_t {
	u32 pid;
};

int write_watch(struct pt_regs *ctx){
	struct data_t data = {};

	data.pid = bpf_get_current_pid_tgid();
	
	events.perf_submit(ctx, &data, sizeof(data));

	return 0;
}
