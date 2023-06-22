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
  u8 comm[256];
} event;

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const event *unused __attribute__((unused));

SEC("kprobe/sys_sendto")
int tp_sendto(struct pt_regs *ctx) {
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  u32 pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns).inum;
  u32 mnt_ns = BPF_CORE_READ(t, nsproxy, mnt_ns, ns).inum;
  struct pt_regs *real_regs;
  real_regs = (struct pt_regs *)PT_REGS_PARM1(ctx);

  if (pid_ns == PROC_PID_INIT_INO) {
    return 0;
  }

  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;

  event *task_info;

  task_info = bpf_ringbuf_reserve(&events, sizeof(event), 0);
  if (!task_info) {
    return 0;
  }

  task_info->pid = tgid;
  task_info->pid_ns = pid_ns;
  task_info->mnt_ns = mnt_ns;
  bpf_probe_read(&task_info->comm, sizeof(task_info->comm),
                 (void *)PT_REGS_PARM2_CORE(real_regs));

  bpf_ringbuf_submit(task_info, 0);

  return 0;
}