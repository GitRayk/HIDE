#include "output.h"

static void set_ether(struct sk_buff *skb) {
    unsigned char hw[6];
    memset(hw, 0xFF, 6);
    eth_header(skb, skb->dev, ETH_P_IPV6, hw, NULL, 0);
}

static int csum_calculate(struct sk_buff *skb) {
    struct ipv6hdr *ipv6_header = NULL;
    unsigned short *transport_checksum;
    unsigned short transport_len;

    transport_len = skb->tail - skb->transport_header;
    ipv6_header = ipv6_hdr(skb);

    if(ipv6_header->nexthdr == IPPROTO_ICMPV6)  transport_checksum = &(icmp6_hdr(skb)->icmp6_cksum);
    else if(ipv6_header->nexthdr == IPPROTO_TCP)    transport_checksum = &(((struct tcphdr *)skb_transport_header(skb))->check);
    else if(ipv6_header->nexthdr == IPPROTO_UDP)    transport_checksum = &(((struct udphdr *)skb_transport_header(skb))->check);
    else {
        printk("Unrecognized next header: %#02x", ipv6_header->nexthdr); 
        return -1;
    }

    // printk("csum: %u, ip_summed: %d, transport_csum: %u", skb->csum, skb->ip_summed, *transport_checksum);

    skb->csum = 0;
    *transport_checksum = 0;

    skb->csum = csum_partial(skb_transport_header(skb), transport_len, skb->csum);
    *transport_checksum = csum_ipv6_magic(&ipv6_header->saddr, &ipv6_header->daddr, transport_len, ipv6_header->nexthdr, skb->csum);
    skb->ip_summed = CHECKSUM_NONE;     // 通知硬件不需要做任何处理，校验和已经由纯软实现

    return 0;
}

unsigned int hook_output(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    char *char_addr = NULL;
    char encrypt_addr[ENCRYPT_SIZE] = {0};
    char AID[8];
    unsigned int sn;
    char aes_key[16];
    unsigned int time_stamp; 

    //  发送端发送时从 kern_ioctl 模块查询自己加密信息
    get_aid(AID);
    get_sn(&sn);
    get_aes_key(aes_key);

    // 获取 IID || EEA
    time_stamp = (unsigned int)ktime_get();
    aes_encrypt(AID, (char*)&time_stamp, (char*)&sn, aes_key, encrypt_addr);
     // 修改 IPv6 源地址，必须得在添加扩展报头之前修改，因为扩展报头中的 IPC 依赖修改后的 IP 地址
    char_addr = (char*)&(ipv6_hdr(skb)->saddr);
    memcpy(char_addr + 8, encrypt_addr, 8);

    // 由于修改了源地址，所以需要重新计算上层校验和
    if(csum_calculate(skb) == -1)
        return NF_DROP;

    // 添加扩展报头，需要加密时使用的 ts、sn 和加密结果中的 eea
    add_extended_header(skb, AID, time_stamp, sn, encrypt_addr + 8);

    // 设置以太头并发送到网络设备队列
    set_ether(skb);
    
    dev_queue_xmit(skb);

    return NF_STOLEN;
}

static struct nf_hook_ops nfho = {
    .hook = hook_output,
    .pf = NFPROTO_IPV6,
    .hooknum = NF_INET_POST_ROUTING,
    .priority = NF_IP6_PRI_LAST
};

int output_init(void) {
    nf_register_net_hook(&init_net, &nfho);
    return 0;
}

void output_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
}
    
    
    
