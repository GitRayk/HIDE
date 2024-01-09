#include "input.h"

static void set_ether(struct sk_buff *skb) {
    struct ethhdr *eth = eth_hdr(skb);
    if(NULL != skb->dev && NULL != skb->dev->dev_addr) {
        memcpy(eth->h_dest, skb->dev->dev_addr, 6);
    }

    skb->pkt_type = PACKET_HOST;
}

unsigned int hook_input(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    // 接受端接受到数据后，首先根据数据包的 mac 地址查询使用的加密密钥，然后对 IID || EEA 解密得到 AID
    // 然后再根据这个 AID 及其他信息去验证 IPC 是否正确，正确则放行数据包
    struct ethhdr *eth_header = eth_hdr(skb);
    LABEL_HEADER *label_hdr = NULL;
    const TERMINAL_ENCRYPT_INFO *tinfo = NULL; 
    const TERMINAL_IP_INFO *ip_info = NULL;
    char *char_addr = NULL;
    char plaintext[ENCRYPT_SIZE];   // 保存解密数据，即 AID || TS || SN

    tinfo = find_terminal_of_mac(eth_header->h_source);
    if(tinfo == NULL) {
        printk(KERN_INFO "Can't find any aes key of Source MAC Address: %pM\n", eth_header->h_source);
        return NF_DROP;     // 如果查不到对应的密钥，直接丢弃数据包
    }

    label_hdr = skb_label_header(skb);
    if(label_hdr != NULL) {
        char_addr = (char*)&(ipv6_hdr(skb)->saddr);
        aes_decrypt(tinfo->encrypt_key, char_addr + 8, label_hdr->eea, plaintext);  // 解密后前 8 个字节是 AID

        if (remove_extended_header(skb, plaintext) == -1)
            return NF_DROP;
        
        // set_ether(skb);
        // 得到 AID 之后，需要根据 AID 还原出真实的源 IPv6 地址再交给上层处理
        ip_info = find_terminal_of_aid(plaintext);
        if(ip_info == NULL) {
            printk(KERN_INFO "Can't find any ipv6 address of AID: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X\n",
                    plaintext[0], plaintext[1], plaintext[2], plaintext[3], plaintext[4], plaintext[5], plaintext[6], plaintext[7]);
            return NF_DROP;
        }
        printk("数据包源IP[%pI6]对应的真实地址为[%pI6]", &(ipv6_hdr(skb)->saddr), ip_info->ip6);
        memcpy(&(ipv6_hdr(skb)->saddr), ip_info->ip6, 16);

        return NF_ACCEPT;
    }

    // 当没有使用地址标签的系统时，数据包正常放行？还是丢弃？如果是后者，那还需要在该函数中给NDP开个后门
    return NF_ACCEPT;
}

static struct nf_hook_ops nfho = {
    .hook = hook_input,
    .pf = PF_INET6,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP6_PRI_FIRST
};

int input_init(void) {
    nf_register_net_hook(&init_net, &nfho);
    return 0;
}

void input_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
}
    
    
    
