#include "output.h"

// AID 应该有一套 ioctl 的逻辑，由用户空间生成并下发，aes_key 同理，这里先简单实现一下
static u_int64_t AID;
static char aes_key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
};

static void set_ether(struct sk_buff *skb) {
    unsigned char hw[6];
    memset(hw, 0xFF, 6);
    eth_header(skb, skb->dev, ETH_P_IPV6, hw, NULL, 0);
}

unsigned int hook_output(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    char *char_addr = NULL;
    int sn;
    char encrypt_addr[ENCRYPT_SIZE] = {0};

    add_extended_header(skb);

    // 对 IPv6 地址进行加密
    get_random_bytes(&sn, sizeof(sn));
    aes_encrypt((char*)&AID, (char*)&sn, aes_key, encrypt_addr);
    char_addr = (char*)&(ipv6_hdr(skb)->saddr);
    memcpy(char_addr + 8, encrypt_addr, 8);

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
    get_random_bytes(&AID, sizeof(AID));
    nf_register_net_hook(&init_net, &nfho);
    return 0;
}

void output_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
}
    
    
    
