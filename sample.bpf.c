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
  char comm[256];
} event;

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const event *unused __attribute__((unused));

static __always_inline u32 get_task_pid_vnr(struct task_struct *task) {
  struct pid *pid = BPF_CORE_READ(task, thread_pid);
  unsigned int level = BPF_CORE_READ(pid, level);
  return BPF_CORE_READ(pid, numbers[level].nr);
}

static __always_inline u32 get_task_ns_tgid(struct task_struct *task) {
  struct task_struct *group_leader = BPF_CORE_READ(task, group_leader);
  return get_task_pid_vnr(group_leader);
}

#define DIR_PROC "/proc/"

static __always_inline int isProcDir(char *path) {
  char procDir[] = DIR_PROC;
  int i = 0;
  while (i < sizeof(DIR_PROC) - 1 && path[i] != '\0' && path[i] == procDir[i]) {
    i++;
  }

  if (i == sizeof(DIR_PROC) - 1) {
    return 1;
  }

  return 0;
}

#define FILE_ENVIRON "/environ"

static __always_inline int isEnviron(char *path) {
  char envFile[] = FILE_ENVIRON;
  int i = 0;
  while (i < sizeof(FILE_ENVIRON) - 1 && path[i] != '\0' &&
         path[i] == envFile[i]) {
    i++;
  }

  if (i == sizeof(FILE_ENVIRON) - 1) {
    return 1;
  }

  return 0;
}

SEC("lsm/file_open")
int BPF_PROG(enforce_file, struct file *file) {
  // struct path f_path = BPF_CORE_READ(file, f_path);
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  u32 pid_ns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns).inum;
  u32 mnt_ns = BPF_CORE_READ(t, nsproxy, mnt_ns, ns).inum;

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

  task_info->pid = get_task_ns_tgid(t);
  task_info->pid_ns = pid_ns;
  task_info->mnt_ns = mnt_ns;
  bpf_d_path(&file->f_path, task_info->comm, 256);

  if (!isProcDir(task_info->comm)) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }

  long envpid;
  int count =
      bpf_strtol(task_info->comm + sizeof(DIR_PROC) - 1, 10, 0, &envpid);
  if (count < 0) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }
  u8 envstart = sizeof(DIR_PROC) + count - 1;
  if (envstart < 80 && !isEnviron(task_info->comm + envstart)) {
    bpf_ringbuf_discard(task_info, 0);
    return 0;
  }

  if (envpid != task_info->pid) {
    bpf_printk("pid: %d comm: %s, count: %d, new_pid: %d\n", task_info->pid,
               task_info->comm, count, envpid);
    bpf_ringbuf_submit(task_info, 0);
    return -13;
  }

  bpf_ringbuf_discard(task_info, 0);
  return 0;
}