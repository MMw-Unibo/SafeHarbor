#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TEST_MESSAGE_LEN 100

/*struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct user_msg_t);
} test_map SEC(".maps");*/

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} output SEC(".maps");

SEC("ksyscall/execve")
int BPF_KPROBE_SYSCALL(test, const char *pathname) 
{
    char msg[TEST_MESSAGE_LEN];

    char *test_message = "This is a test";
    
    bpf_probe_read_kernel(msg, sizeof(msg), test_message);
    bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
    
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
