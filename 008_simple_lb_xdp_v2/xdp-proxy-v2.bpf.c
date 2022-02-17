#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp-proxy-v2.h"

/*define a hashmap for userspace to update service endpoints*/

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, struct endpoints);
    __uint(max_entries, 1024);
} services SEC(".maps");

/* Refer https://github.com/facebookincubator/katran/blob/main/katran/lib/bpf/csum_helpers.h#L30 */

static __always_inline __u16 csum_fold_helper(__u64 csum)
{
    int i;
#pragma unroll
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16 ipv4_csum(struct iphdr *iph)
{
    iph->check = 0;
    unsigned long long csum =
        bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}

SEC("xdp")
int xdp_proxy(struct xdp_md *ctx)
{
    /*数据段头指针*/
    void *data = (void *)(long)ctx->data;
    /*数据段尾指针*/
    void *data_end = (void *)(long)ctx->data_end;
    /*定义以太网帧头指针，指向数据段头*/
    struct ethhdr *eth = data;

    /* abort on illegal packets*/
    if (data + sizeof(struct ethhdr) > data_end)
    {
        /*数据包丢弃并记录错误*/
        return XDP_ABORTED;
    }
    /* do nothing for ipv4 packets*/
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return XDP_PASS;
    }

    /*取ip头*/
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
    {
        return XDP_ABORTED;
    }
    /*如果不是tcp报文,pass*/
    if (iph->protocol != IPPROTO_TCP)
    {
        return XDP_PASS;
    }
}