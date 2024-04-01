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
    struct net_device *dev;
    struct in6_addr net_device_ip, saddr, daddr;
    const TERMINAL_AID_INFO *aid_info = NULL;
    TERMINAL_ENCRYPT_INFO fake_encrypt_info = {
        .mac = "\x00\x00\x00\x00\x00\x00",
        .encrypt_key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    };

    // 通过netlink发送给用户空间的信息
    UPLOAD_MES mesg;
    s64 start_time = 0, end_time = 0;   // 记录解密的开始时间和结束时间，以计算开销

    tinfo = find_terminal_of_mac(eth_header->h_source);
    if(tinfo == NULL) {
        // printk(KERN_INFO "Can't find any aes key of Source MAC Address: %pM\n", eth_header->h_source);
        // return NF_ACCEPT;     // 如果查不到对应的密钥，直接接受该数据包
        // 在该分支中，不提前设置对称密钥，而是让所有的终端都是用同样的密钥
        tinfo = &fake_encrypt_info;
    }

    label_hdr = skb_label_header(skb);
    if(label_hdr != NULL) {
        char_addr = (char*)&(ipv6_hdr(skb)->saddr);
        start_time = ktime_to_ns(ktime_get());
        aes_decrypt(tinfo->encrypt_key, char_addr + 8, label_hdr->eea, plaintext);  // 解密后前 8 个字节是 AID

        // 解密完成后，通过netlink向用户空间的进程发送消息
        memset((char*)&mesg, 0, sizeof(UPLOAD_MES));
        dev = state->in;
        daddr = ipv6_hdr(skb)->daddr;
        saddr = ipv6_hdr(skb)->saddr;
        if (ipv6_dev_get_saddr(&init_net, dev, &daddr, 0, &net_device_ip) != 0) {
            printk("Can't find net device [%s]ipv6 to %pI6", dev->name, &daddr);
            memset(mesg.source, 0, 8);
        } 
        else {
            aid_info = find_terminal_of_ip6((char*)&net_device_ip);
            if(aid_info == NULL) {
                printk("Can't get aid of ipv6: %pI6", &net_device_ip);
                memset(mesg.source, 0, 8);
            }
            else {
                memcpy(mesg.source, aid_info->aid, 8);
            }
        }
        
        memcpy(mesg.label, char_addr, 16);
        memcpy(mesg.aid, plaintext, 8);

        if (remove_extended_header(skb, plaintext) == -1) {
            end_time = ktime_to_ns(ktime_get());
            mesg.delayTime = end_time - start_time;
            strncpy(mesg.states, "bad", 8);
            strncpy(mesg.notes, "IPC ERROR", 24);
            channel_send(NL_UPLOAD_LOG, (char*)&mesg, sizeof(UPLOAD_MES));
            return NF_DROP;
        }
        else {
            //  remove_extended_header 的返回值为正数 (因为返回值为 -2 的情况在该代码块中不可能发生)
            end_time = ktime_to_ns(ktime_get());
            mesg.delayTime = end_time - start_time;
            strncpy(mesg.states, "good", 8);
            strncpy(mesg.notes, "", 24);
            channel_send(NL_UPLOAD_LOG, (char*)&mesg, sizeof(UPLOAD_MES));
        }
        
        // set_ether(skb);
        // 得到 AID 之后，需要根据 AID 还原出真实的源 IPv6 地址再交给上层处理
        ip_info = find_terminal_of_aid(plaintext);
        if(ip_info == NULL) {
            printk(KERN_INFO "Can't find any ipv6 address of AID: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X\n",
                    plaintext[0], plaintext[1], plaintext[2], plaintext[3], plaintext[4], plaintext[5], plaintext[6], plaintext[7]);
            channel_send(NL_REQUEST_IP6, plaintext, 8);
            return NF_DROP;
        }
        printk("数据包源IP[%pI6]对应的真实地址为[%pI6]", &(ipv6_hdr(skb)->saddr), ip_info->ip6);
        memcpy(&(ipv6_hdr(skb)->saddr), ip_info->ip6, 16);

        return NF_ACCEPT;
    }

    // 当存在对称密钥，但是该数据包没有携带地址标签扩展报头时，数据包正常放行？还是丢弃？如果是后者，那还需要在该函数中给NDP开个后门
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
    
    
    
