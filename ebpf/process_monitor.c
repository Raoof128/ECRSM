// eBPF process and network monitor (educational, read-only)
// Captures execve, connect, ptrace, memfd_create, mmap(PROT_EXEC)
// Emits events via perf buffer for user-space processing.

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/mman.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

// Minimal tracepoint context for sys_enter to avoid dependency on vmlinux.h
struct trace_event_raw_sys_enter {
	struct trace_entry ent;
	long id;
	unsigned long args[6];
};

#define FILE_NAME_LEN 256
#define EVENT_TYPE_LEN 16

struct event_t {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;
    __u32 dst_ip;       // IPv4
    __u16 dst_port;     // network order
    __u8  proto;        // IPPROTO_*
    char comm[TASK_COMM_LEN];
    char filename[FILE_NAME_LEN];
    char event_type[EVENT_TYPE_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC("maps");

static __always_inline __u32 get_ppid(struct task_struct *task) {
    // BPF CO-RE to safely read parent TGID
    __u32 ppid = 0;
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    if (parent)
        ppid = BPF_CORE_READ(parent, tgid);
    return ppid;
}

static __always_inline int submit_event(void *ctx, struct event_t *evt, const char *etype) {
    __builtin_memset(evt->event_type, 0, EVENT_TYPE_LEN);
    bpf_probe_read_kernel_str(evt->event_type, EVENT_TYPE_LEN, etype);
    return bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));
}

static __always_inline void fill_task_context(struct event_t *evt) {
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->uid = bpf_get_current_uid_gid() & 0xffffffff;
    evt->gid = bpf_get_current_uid_gid() >> 32;
    evt->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    evt->ppid = get_ppid(task);
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event_t evt = {};
    fill_task_context(&evt);

    const char *filename = (const char *)ctx->args[0];
    if (filename)
        bpf_probe_read_user_str(evt.filename, FILE_NAME_LEN, filename);

    submit_event(ctx, &evt, "exec");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx) {
    struct event_t evt = {};
    fill_task_context(&evt);

    const struct sockaddr *uservaddr = (const struct sockaddr *)ctx->args[1];
    int addrlen = (int)ctx->args[2];

    if (uservaddr && addrlen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in sa = {};
        bpf_probe_read_user(&sa, sizeof(sa), uservaddr);
        if (sa.sin_family == AF_INET) {
            evt.dst_ip = sa.sin_addr.s_addr;
            evt.dst_port = sa.sin_port; // network byte order
            evt.proto = IPPROTO_TCP; // connect currently implies TCP
        }
    }

    submit_event(ctx, &evt, "connect");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int handle_ptrace(struct trace_event_raw_sys_enter *ctx) {
    struct event_t evt = {};
    fill_task_context(&evt);
    submit_event(ctx, &evt, "ptrace");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int handle_memfd(struct trace_event_raw_sys_enter *ctx) {
    struct event_t evt = {};
    fill_task_context(&evt);

    const char *name = (const char *)ctx->args[0];
    if (name)
        bpf_probe_read_user_str(evt.filename, FILE_NAME_LEN, name);

    submit_event(ctx, &evt, "memfd");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int handle_mmap(struct trace_event_raw_sys_enter *ctx) {
    struct event_t evt = {};
    fill_task_context(&evt);

    unsigned long prot = ctx->args[2];
    if (prot & PROT_EXEC) {
        submit_event(ctx, &evt, "mmap_exec");
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
