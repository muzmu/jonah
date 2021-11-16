#include <linux/sched.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/net.h>
#include <uapi/linux/un.h>
#include <net/af_unix.h>

#define MAX_SEG_SIZE 1024 * 50
#define MAX_SEGS_PER_MSG 10

struct packet {
    u32 pid;
    u32 peer_pid;
    u32 len;
    char comm[TASK_COMM_LEN];
    char data[MAX_SEG_SIZE];
};

BPF_PERF_OUTPUT(events);
BPF_ARRAY(filter_arr, u32, 1);
BPF_ARRAY(packet_array, struct packet, NR_CPUS);
BPF_PERF_OUTPUT(unix_sock_events);

struct data_t {
	u32 pid;
	char str[8];
	char comm[TASK_COMM_LEN];
	char filename[DNAME_INLINE_LEN];
};

static int is_filter_proc(char filename[]){
	return (filename[0]=='d' && filename[1] == 'o' && filename[2] == 'c' 
	&& filename[3] == 'k' && filename[4] == 'e' && filename[5] == 'r' 
	&& filename[6] == 'd');
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

int do_unix_sock(struct pt_regs *ctx, struct socket *sock, struct msghdr *msg, size_t len)
{
    struct packet *packet;
    struct unix_address *addr;
    char *buf;
    unsigned int n, match = 0, offset;
    struct iov_iter *iter;
    const struct kvec *iov;
    struct pid *peer_pid;

    n = bpf_get_smp_processor_id();
    packet = packet_array.lookup(&n);
    if (packet == NULL)
        return 0;

    packet->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&packet->comm, sizeof(packet->comm));
    packet->peer_pid = sock->sk->sk_peer_pid->numbers[0].nr;

    iter = &msg->msg_iter;
    if ((iter->type & WRITE) == 0 || iter->iov_offset != 0) {
        packet->len = len;
        unix_sock_events.perf_submit(ctx, packet, offsetof(struct packet, data));
        return 0;
    }

    iov = iter->kvec;

    #pragma unroll
    for (int i = 0; i < MAX_SEGS_PER_MSG; i++) {
        if (i >= iter->nr_segs)
            break;

        packet->len = iov->iov_len;

        buf = iov->iov_base;
        n = iov->iov_len;
        bpf_probe_read_kernel(&packet->data, n > sizeof(packet->data) ? sizeof(packet->data) : n, buf);

        n += offsetof(struct packet, data);
        unix_sock_events.perf_submit(ctx, packet, n > sizeof(*packet) ? sizeof(*packet) : n);

        iov++;
    }

    return 0;
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

	if(is_filter_proc(data.comm) && is_filter_pid(pid) < 0)
		register_filter_pid(pid);
	
	if(is_filter_pid(pid) || is_filter_pid(t->real_parent->pid))
		events.perf_submit(ctx, &data, sizeof(data));

	return 0;
}

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

	if(is_filter_proc(data.comm) && is_filter_pid(pid) < 0)
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

	if(is_filter_proc(data.comm) && is_filter_pid(pid) < 0)
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

	if(is_filter_proc(data.comm) && is_filter_pid(pid) < 0)
		register_filter_pid(pid);
	
	if(is_filter_pid(pid) || is_filter_pid(t->real_parent->pid))
		events.perf_submit(ctx, &data, sizeof(data));

	return 0;
}
