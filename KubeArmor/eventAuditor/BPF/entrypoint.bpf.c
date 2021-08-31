// Loader function
// +build ignore

#include "entrypoint.bpf.h"

// #define SYS_OPEN            1
// #define SYS_CONNECT         2
// #define SYS_EXECVE          3

SEC("kprobe/sys_open")
int kprobe__sys_open(void *ctx)
{
	bpf_trace_printk("sys_open");
    return 0;
}

SEC("kprobe/sys_openat")
int kprobe__sys_openat(void *ctx)
{
	bpf_trace_printk("sys_openat");
    return 0;
}

SEC("kprobe/sys_execve")
int kprobe__sys_execve(void *ctx)
{
    bpf_trace_printk("sys_execve");
    return 0;
}

SEC("kprobe/sys_execveat")
int kprobe__sys_execveat(void *ctx)
{
    bpf_trace_printk("sys_execveat");
    return 0;
}

SEC("kprobe/sys_socket")
int kprobe__sys_socket(void *ctx)
{
	bpf_trace_printk("sys_socket");
    return 0;
}

SEC("kprobe/sys_bind")
int kprobe__sys_bind(void *ctx)
{
    bpf_trace_printk("sys_bind");
    return 0;
}

SEC("kprobe/sys_listen")
int kprobe__sys_listen(void *ctx)
{
    bpf_trace_printk("sys_listen");
    return 0;
}

SEC("kprobe/sys_accept")
int kprobe__sys_accept(void *ctx)
{
    bpf_trace_printk("sys_accept");
    return 0;
}

SEC("kprobe/sys_connect")
int kprobe__sys_connect(void *ctx)
{
    bpf_trace_printk("sys_connect");
    return 0;
}

// Example of passing data using a perf map
// Similar to bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count();}'
BPF_PERF_OUTPUT(events)
SEC("raw_tracepoint/sys_enter")
int raw_tracepoint__sys_enter(void *ctx)
{
    char data[100];
    bpf_get_current_comm(&data, 100);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, 100);
    return 0;
}
