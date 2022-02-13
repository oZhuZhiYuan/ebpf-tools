#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE 64
#define TOTAL_MAX_ARGS 5
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)
#define LAST_ARG (FULL_MAX_ARGS_ARR - ARGSIZE)

struct data_t
{
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    int retval;
    unsigned int args_size;
    char argv[FULL_MAX_ARGS_ARR];
};

BPF_PERF_OUTPUT(events);
BPF_HASH(tasks, u32, struct data_t);

// 从用户空间读取字符串
static int __bpf_read_arg_str(struct data_t *data, const char *ptr)
{
    if (data->args_size > LAST_ARG)
    {
        return -1;
    }
    int ret = bpf_probe_read_user_str(&data->argv[data->args_size], ARGSIZE, (void *)ptr);
    if (ret > ARGSIZE || ret < 0)
    {
        return -1;
    }
    data->args_size += (ret - 1);

    return 0;
}

// 定义sys_enter_exeve 跟踪点处理函数.
TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    // variables definitions
    unsigned int ret = 0;
    const char **argv = (const char **)(args->argv);

    // get the pid and comm
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid();
    data.pid = pid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    /*get ppid*/
    struct task_struct *task;
    task = (struct task_struct*)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;

    // get the binary name (first argment)
    if (__bpf_read_arg_str(&data, (const char *)argv[0]) < 0)
    {
        goto out;
    }
    // get other arguments (skip first arg because it has already been read)
#pragma unroll
    for (int i = 1; i < TOTAL_MAX_ARGS; i++)
    {
        if (__bpf_read_arg_str(&data, (const char *)argv[i]) < 0)
        {
            goto out;
        }
    }

out:
    // store the data in hash map
    tasks.update(&pid, &data);
    return 0;
}

// 定义sys_exit_exeve 跟踪点处理函数.
TRACEPOINT_PROBE(syscalls, sys_exit_execve)
{
    // 从hash映射中获取data
    u32 pid = bpf_get_current_pid_tgid();
    struct data_t *data = tasks.lookup(&pid);

    // 填充返回值并提交性能事件映射中
    if (data != NULL)
    {
        data->retval = args->ret;
        events.perf_submit(args, data, sizeof(struct data_t));

        // 清理进程信息
        tasks.delete(&pid);
    }
    return 0;
}