#include <stdio.h>
#include <signal.h>

#include <linux/bpf.h>
#include <test_progs.h>

#define FILE_CREAT 	"bpf_progs/creat_prog.o"
#define FILE_MOD 	"bpf_progs/mod_prog.o"
#define NET_IN		"bpf_progs/net_in_prog.o"
#define NET_OUT		"bpf_progs/net_out_prog.o"

int init(void) {
	// attach BPF programs defined above **look into renaming
	int creat_progfd, mod_progfd, 
	net_in_progfd, net_out_progfd;

	struct bpf_object *creat_obj, *mod_obj, 
					  *net_in_obj, *net_out_obj;
	
	if(bpf_prog_load(FILE_CREAT, BPF_PROG_TYPE_))
	

	// register signal handlers

	// register daemon to handle reading buffers

	printf("starting jonah...\n");
}

void filter(char* line) {
	/* filter through line of data
	if the line is part of the docker build no change
	else set line = "" */
}

void check_hooks(int sig) {
	// checks eBPF hook buffers, will be on a timer, triggered by SIGALRM
}

void monitor_procs(int sig) {
	// process monitor for Docker build, triggered by SIGCHLD
}

int main() {
	init();
}
