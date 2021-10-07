#include <stdio.h>

#include <linux/bpf.h>

int init(void) {
	// attach BPF programs
	fprintf("starting jonah...");
}

void filter(char* line) {
	/* filter through line of data
	if the line is part of the docker build no change
	else set line = "" */
}

void check_hooks() {
	// checks eBPF hook buffers
}

void monitor_procs() {
	// process monitor for Docker build
}


