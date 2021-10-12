#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

SEC("prog")
int creat_watch(){
    return 0;
}