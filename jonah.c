#include <stdio.h>
#include <signal.h>
//test
int init(void) {
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
