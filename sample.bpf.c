// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

typedef struct {
  u32 pid;
  u32 pid_ns;
  u32 mnt_ns;
  u8 comm[80];
} event;

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const event *unused __attribute__((unused));

SEC("kprobe/sys_execve")
int kprobe_execve(struct pt_regs *ctx) {
  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;

  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  u32 pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns).inum;
  u32 mnt_ns = BPF_CORE_READ(t, nsproxy, mnt_ns, ns).inum;

  event *task_info;

  task_info = bpf_ringbuf_reserve(&events, sizeof(event), 0);
  if (!task_info) {
    return 0;
  }

  task_info->pid = tgid;
  task_info->pid_ns = pid_ns;
  task_info->mnt_ns = mnt_ns;
  bpf_get_current_comm(&task_info->comm, 80);

  bpf_ringbuf_submit(task_info, 0);

  return 0;
}