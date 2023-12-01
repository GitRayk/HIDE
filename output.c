#include "output.h"

static void set_ether(struct sk_buff *skb) {
    unsigned char hw[6];
    memset(hw, 0xFF, 6);
    eth_header(skb, skb->dev, ETH_P_IPV6, hw, NULL, 0);
}

unsigned int hook_output(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    char *char_addr = NULL;
    char encrypt_addr[ENCRYPT_SIZE] = {0};
    u_int64_t AID;
    unsigned int sn;
    char aes_key[16];
    unsigned int time_stamp; 

    // 从 kern_ioctl 模块中获取加密所需信息（耦合度高）
    // 这里感觉可以加一个验证是否获得了 AID，再决定要不要将数据包发送出去，即只有获得入网许可的才可以通信（实际AID分配是由用户空间做）
    get_aid(&AID);
    get_sn(&sn);
    get_aes_key(aes_key);

    // 获取 IID || EEA
    time_stamp = (unsigned int)ktime_get();
    aes_encrypt((char*)&AID, (char*)&time_stamp, (char*)&sn, aes_key, encrypt_addr);
     // 修改 IPv6 源地址，必须得在添加扩展报头之前修改，因为扩展报头中的 IPC 依赖修改后的 IP 地址
    char_addr = (char*)&(ipv6_hdr(skb)->saddr);
    memcpy(char_addr + 8, encrypt_addr, 8);

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
    
    
    
