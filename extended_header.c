#include "extended_header.h"

static void debug_print_packet(const struct sk_buff *skb) {
    unsigned char *byte = skb->data;
    int i = skb->len;
    printk("####################");
    while(i > 0) {
        printk("%#x %#x %#x %#x    %#x %#x %#x %#x", *byte, *(byte+1), *(byte+2), *(byte+3), *(byte+4), *(byte+5), *(byte+6), *(byte+7));
        byte += 8;
        i -= 8;
    }
    printk("####################");
}

// 调用 get_ipc 的前提条件是数据包有 IP 头，所以不要在去掉了 IP 头之后才调用，同时要保证 transport_header 和 network_header 的值正确
static void get_ipc(struct sk_buff *skb,  const char *AID, const char* EEA, unsigned int eea_len, unsigned int ts, unsigned sn, char *target) {
    char *transport_hash = NULL;
    char *hash_plaintext = NULL;
    unsigned int plaintext_len = IPV6_ADDRESS_LEN+ IPV6_ADDRESS_LEN + 8 + eea_len + sizeof(ts) + sizeof(sn) + get_digest_size();
    char *plaintext_buff = NULL;    // 用于拼接

    // 将 (源IP || 目的 IP || AID  || EEA || TS || SN || Hash(传输层)) 进行一次哈希得到扩展报头中的 IPC 字段
    // 所以，这里目的端要怎么获取源设备的 AID 呢？AID 的获取有两种方法，一种是提前由用户态的程序和密钥一起下发，另一种是先对 IID || EEA 进行解密来获得。（有点怪我感觉
    // 如果是解密得到的，那解密之前需要知道这个数据包加密所使用的密钥，所以应该有 MAC - 密钥 的映射关系
    // 这里使用解密得到 
    transport_hash = kmalloc(get_digest_size(), GFP_KERNEL);
    get_hash(skb_transport_header(skb), skb->tail - skb->transport_header, transport_hash);
    hash_plaintext = kmalloc(plaintext_len, GFP_KERNEL);
    plaintext_buff = hash_plaintext;
    memcpy(plaintext_buff, (char*)&(ipv6_hdr(skb)->saddr), IPV6_ADDRESS_LEN);
    plaintext_buff += IPV6_ADDRESS_LEN;
    memcpy(plaintext_buff, (char*)&(ipv6_hdr(skb)->daddr), IPV6_ADDRESS_LEN);
    plaintext_buff += IPV6_ADDRESS_LEN;
    memcpy(plaintext_buff, AID, 8);
    plaintext_buff += 8;
    memcpy(plaintext_buff, EEA, eea_len);
    plaintext_buff += eea_len;
    memcpy(plaintext_buff, (char*)&ts, sizeof(ts));
    plaintext_buff += sizeof(ts);
    memcpy(plaintext_buff, (char*)&sn, sizeof(sn));
    plaintext_buff += sizeof(sn);
    memcpy(plaintext_buff, transport_hash, get_digest_size());
    plaintext_buff += get_digest_size();

    kfree(transport_hash);
    transport_hash = NULL, plaintext_buff = NULL;    

    get_hash(hash_plaintext, plaintext_len, target);
    kfree(hash_plaintext);
    hash_plaintext = NULL;
}

LABEL_HEADER *skb_label_header(struct sk_buff *skb) {
    struct ipv6hdr *ipv6_header;
    ipv6_header = ipv6_hdr(skb);
    if(ipv6_header->nexthdr != IPPROTO_LABEL)   return NULL;
    else    return (LABEL_HEADER*)(ipv6_header+1);
}

int add_extended_header(struct sk_buff *skb, const char *AID, unsigned int ts, unsigned sn, const unsigned char *eea) {
    struct ipv6hdr ipv6_header;
    LABEL_HEADER *extended_header = NULL;
    short payload_len;
    char *IPC = NULL;

    // 首先计算 IPC
    IPC = kmalloc(get_digest_size(), GFP_KERNEL);
    get_ipc(skb, AID, eea, 8, ts, sn, IPC);

    // 复制备份原IPv6基本报头然后将其移除
    pskb_expand_head(skb, sizeof(LABEL_HEADER), 0, GFP_ATOMIC);
    memcpy(&ipv6_header, skb->data, IPV6_HEADER_LEN);
    skb_pull(skb, IPV6_HEADER_LEN);

    // 创建自定义扩展报头
    extended_header = skb_push(skb, sizeof(LABEL_HEADER));
    memset(extended_header, 0, sizeof(LABEL_HEADER));
    extended_header->next_header = ipv6_header.nexthdr;
    extended_header->length = htons(sizeof(LABEL_HEADER));
    extended_header->timestamp = ts;
    extended_header->sequence = sn;
    memcpy(extended_header->eea, eea, 8);
    memcpy(extended_header->IPC, IPC, get_digest_size());

    kfree(IPC);
    IPC = NULL;

    // 恢复IPv6基本报头
    ipv6_header.nexthdr = IPPROTO_LABEL;
    payload_len = ntohs(ipv6_header.payload_len);
    payload_len += sizeof(LABEL_HEADER);
    ipv6_header.payload_len = htons(payload_len);

    memcpy(skb_push(skb, IPV6_HEADER_LEN), &ipv6_header, sizeof(struct ipv6hdr));
    // skb->network_header -= sizeof(LABEL_HEADER);
    skb_reset_network_header(skb);
    skb_reset_mac_header(skb);
    
    return 0;
}

int remove_extended_header(struct sk_buff *skb, const char *AID) {
    struct ipv6hdr ipv6_header;
    LABEL_HEADER *extended_header = NULL;
    short payload_len;
    char *IPC = NULL;
    skb->transport_header += sizeof(LABEL_HEADER);

    // 验证 IPC
    IPC = kmalloc(get_digest_size(), GFP_KERNEL);
    extended_header = skb_label_header(skb);
    if(extended_header != NULL) {
        get_ipc(skb, AID, extended_header->eea, 8, extended_header->timestamp, extended_header->sequence, IPC);
        if(strncmp(IPC, extended_header->IPC, get_digest_size()) != 0)  {
            printk("IPC error");
            kfree(IPC);
            return -1;
        }
    }
    kfree(IPC);
    IPC = NULL;

    // 复制备份原IPv6基本报头
    memcpy(&ipv6_header, skb->data, IPV6_HEADER_LEN);
    if(ipv6_header.nexthdr != IPPROTO_LABEL)
	return ipv6_header.nexthdr;

    skb_pull(skb, IPV6_HEADER_LEN);

    // 复制备份扩展报头的内容
    extended_header = (LABEL_HEADER*)skb->data;
    skb_pull(skb, sizeof(LABEL_HEADER));

    // 恢复IPv6基本报头
    ipv6_header.nexthdr = extended_header->next_header;
    payload_len = ntohs(ipv6_header.payload_len);
    payload_len -= sizeof(LABEL_HEADER);
    ipv6_header.payload_len = htons(payload_len);

    memcpy(skb_push(skb, IPV6_HEADER_LEN), &ipv6_header, sizeof(struct ipv6hdr));
    // skb->network_header += sizeof(LABEL_HEADER);
    skb_reset_network_header(skb);

    return IPPROTO_LABEL;
}
