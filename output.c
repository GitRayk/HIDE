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
    unsigned int sn, time_stamp;
    char aes_key[16];
    struct in6_addr net_device_ip, saddr, daddr;
    struct net_device *dev;
    const TERMINAL_AID_INFO *aid_info = NULL;
    const TERMINAL_ENCRYPT_INFO *encrypt_info = NULL;
    struct neighbour *neigh = NULL;
    TERMINAL_ENCRYPT_INFO fake_encrypt_info = {
        .mac = "\x00\x00\x00\x00\x00\x00",
        .encrypt_key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    };

    s64 start_time = ktime_to_ns(ktime_get());

    // 如果这个数据包是邻居请求数据||邻居通告就不进行任何处理
    if(ipv6_hdr(skb)->nexthdr == IPPROTO_ICMPV6 && (icmp6_hdr(skb)->icmp6_type == 135 || icmp6_hdr(skb)->icmp6_type == 136)) {
        return NF_ACCEPT;
    }

    //  通过数据包源IP地址找到对应的aid
    dev = state->out;
    daddr = ipv6_hdr(skb)->daddr;
    saddr = ipv6_hdr(skb)->saddr;
    if (ipv6_dev_get_saddr(&init_net, dev, &daddr, 0, &net_device_ip) != 0) {
        printk("Can't find net device [%s]ipv6 to %pI6", dev->name, &daddr);
        return NF_DROP;
    }

    aid_info = find_terminal_of_ip6((char*)&saddr);
    if(aid_info == NULL) {
        printk("Can't get aid of ipv6: %pI6", &saddr);
        channel_send(NL_REQUEST_AID, (char *)&saddr, 16);
        return NF_DROP;
    }
    memcpy(AID, aid_info->aid, 8);
    sn=aid_info->sn;

    // 由于数据包要由下一跳，所以使用的本机与下一跳之间的对称密钥。即由下一跳mac映射密钥，由于钩子函数在网络层，所以通过邻居表找到目的IP的下一跳mac
    neigh = neigh_lookup(&nd_tbl, &daddr, dev);
    if (neigh != NULL && (neigh->nud_state == NUD_REACHABLE || neigh->nud_state == NUD_PERMANENT)) {
        encrypt_info = find_terminal_of_mac(neigh->ha);
        if(encrypt_info == NULL) {
            // printk("Can't get encryption info of mac: %pM", neigh->ha);
            // 当找到下一跳之后，发现与下一跳之间没有对称密钥，无法进行加密，则直接按原数据包发送（适应非协作网络）
            // return NF_ACCEPT;
            encrypt_info = &fake_encrypt_info;
        }
        memcpy(aes_key, encrypt_info->encrypt_key, 16);
    } else {
        // 当发现当前邻居表中没有这项或表项失效的时候，没法将数据加密（因为不知道使用哪个对称密钥）
        // 所以必须让这个数据包直接到达数据链路层，然后数据链路层就会发送邻居请求
        //（或者用一个一定会被接收端丢弃的数据包，这样就保证了除了NS，不会产生不携带地址标签扩展报头的有效数据包）
        printk("Can't get mac of ipv6: %pI6", &daddr);     
        return NF_ACCEPT;
    }

    // 获取 IID || EEA
    time_stamp = (unsigned int)ktime_get();
    aes_encrypt(AID, (char*)&time_stamp, (char*)&sn, aes_key, encrypt_addr);
     // 修改 IPv6 源地址，必须得在添加扩展报头之前修改，因为扩展报头中的 IPC 依赖修改后的 IP 地址
    char_addr = (char*)&(ipv6_hdr(skb)->saddr);
    memcpy(char_addr + 8, encrypt_addr, 8);

    // 由于修改了源地址，所以需要重新计算上层校验和（现在由于每一跳都恢复了IP地址，所以不需要重新计算传输层校验和
    //if(csum_calculate(skb) == -1)
    //    return NF_DROP;

    // 添加扩展报头，需要加密时使用的 ts、sn 和加密结果中的 eea
    add_extended_header(skb, AID, time_stamp, sn, encrypt_addr + 8);

    // 设置以太头并发送到网络设备队列
    // set_ether(skb);
    
    // dev_queue_xmit(skb);

    // return NF_STOLEN;
    s64 end_time = ktime_to_ns(ktime_get());
    printk("hook_output function total time: %lld ns", end_time - start_time);
    return NF_ACCEPT;
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
    
    
    
