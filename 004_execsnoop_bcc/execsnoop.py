#!/usr/bin/env python3

from bcc import BPF
from bcc.utils import printb

# 1）加载eBPF代码
b = BPF(src_file="execsnoop.c")

# 2） 输出头部
print("%-6s %-6s %-16s %-3s %s" % ("PID", "PPID","COMM", "RET", "ARGS"))

# 3） 定义事件打印函数
def print_event(cpu, data, size):
    # BCC 自动根据 struct data_t 生存数据结构
    event = b["events"].event(data)
    printb (b"%-6d %-6d %-16s %-3d %-16s " % (event.pid, event.ppid, event.comm, event.retval, event.argv))

# 4） 绑定事件映射和输出函数， 并从映射中循环读取数据
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()