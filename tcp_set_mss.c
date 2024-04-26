#include "tcp_set_mss.h"

static unsigned int set_mss(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct ipv6hdr *iph;
    struct tcphdr *tcph;
    unsigned char *ptr;
    int opt_len;
    u16* mss;

    // 获取 IPv6 数据包头部
    iph = ipv6_hdr(skb);
    if (!iph || iph->nexthdr != IPPROTO_TCP)
        return NF_ACCEPT;

    // 获取 TCP 数据包头部，协商 MSS 的过程一定出现在 SYN 包中，因此其他 TCP 包可以直接放行
    tcph = tcp_hdr(skb);
    if (!tcph || !tcph->syn)
        return NF_ACCEPT;

    // 获取 TCP 选项部分
    ptr = (unsigned char *)tcph + sizeof(struct tcphdr);
    opt_len = (tcph->doff * 4) - sizeof(struct tcphdr);

    // 遍历 TCP 选项，查找 MSS 选项，TCP option 是 TLV 格式，其中 Type 和 Length 都各占一个字节
    while (opt_len > 0) {
        if (*ptr == TCPOPT_MSS && *(ptr + 1) == TCPOLEN_MSS) {
            if (*ptr == TCPOPT_MSS) {
            //if (*(ptr + 1) >= 4) {
                // 减小 MSS 值
                mss = (u16 *)(ptr + 2);
                *mss = ntohs(*mss);
                if (*mss > MSS_DECREASE_AMOUNT) {
                    *mss -= MSS_DECREASE_AMOUNT;
                }
                *mss = htons(*mss);
            }
            break;
        }
        if (*ptr == TCPOPT_EOL) {
        // if (*ptr <= 1) {
            break;
        }
        opt_len -= *(ptr + 1);
        ptr += *(ptr + 1);
    }

    return NF_ACCEPT; // 放行数据包
}

static struct nf_hook_ops nfho = {
    .hook = set_mss,
    .hooknum = NF_INET_LOCAL_OUT, // 本地发送数据包时触发
    .pf = PF_INET6,
    .priority = NF_IP6_PRI_FIRST,
};

int tcp_set_mss_init(void) {
    // 注册 netfilter 钩子
    if (nf_register_net_hook(&init_net, &nfho) < 0) {
        printk(KERN_ERR "Failed to register netfilter hook\n");
        return -1;
    }
    return 0;
}

void tcp_set_mss_exit(void) {
    // 注销 netfilter 钩子
    nf_unregister_net_hook(&init_net, &nfho);
}