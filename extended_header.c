#include "extended_header.h"
#include "debug_util.h"

void debug_print_packet(const struct sk_buff *skb) {
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

void print_ALH(LABEL_HEADER *alh) {
    unsigned char *byte = (unsigned char *)alh;
    int i = 0;
    printk("------------扩展报头数据：");
    while(i < 48) {
        printk("%#02X %#02X %#02X %#02X %#02X %#02X %#02X %#02X", *byte, *(byte+1), *(byte+2), *(byte+3), *(byte+4), *(byte+5), *(byte+6), *(byte+7));
        i += 8;
        byte += 8;
    }
    printk("%#02X %#02X %#02X %#02X", *byte, *(byte+1), *(byte+2), *(byte+3));
    printk("--------------------");
}

// 调用 get_ipc 的前提条件是数据包有 IP 头，所以不要在去掉了 IP 头之后才调用，同时要保证 transport_header 和 network_header 的值正确
static void get_ipc(struct sk_buff *skb,  const char *AID, const char* EEA, unsigned int eea_len, unsigned int ts, unsigned sn, char *target) {
    char *hash_plaintext = NULL;
    unsigned int plaintext_len = IPV6_ADDRESS_LEN+ IPV6_ADDRESS_LEN + 8 + eea_len + sizeof(ts) + sizeof(sn);
    char *plaintext_buff = NULL;    // 用于指示当前的拼接位置
    // 将 (源IP || 目的 IP || AID  || EEA || TS || SN) 进行一次哈希得到扩展报头中的 IPC 字段
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

    plaintext_buff = NULL;    

    get_hash(hash_plaintext, plaintext_len, target);
    kfree(hash_plaintext);
    hash_plaintext = NULL;
}

LABEL_HEADER *skb_label_header(struct sk_buff *skb) {
    struct ipv6hdr *ipv6_header;
    ipv6_header = ipv6_hdr(skb);
    if(ipv6_header->nexthdr == IPPROTO_LABEL)   return (LABEL_HEADER*)(ipv6_header+1);
    else if(ipv6_header->nexthdr == 44) return (LABEL_HEADER*)(skb->data + 48);
    else return NULL;
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
    // print_ALH(extended_header);

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
    struct ipv6hdr *ipv6_header;
    LABEL_HEADER *extended_header = NULL;
    short payload_len;
    char *IPC = NULL;
    // printk("transport_header: %d", skb->transport_header );
    char *header_buff = NULL;
    unsigned int buff_len = 0;

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
        DEBUG_PRINT("IPC 验证通过\n");
        kfree(IPC);
    }
    else {
        printk("There is no Address Label Header");
        kfree(IPC);
        return -2;
    }
    IPC = NULL;

    // 复制备份地址标签报头之前的数据（主要是原IPv6基本报头及可能存在的分片头）
    buff_len = (unsigned char*)extended_header - skb->data;
    // printk("remove protect len: %d", buff_len);
    header_buff = kmalloc(buff_len, GFP_KERNEL);
    memcpy(header_buff, skb->data, buff_len);
    ipv6_header = (struct ipv6hdr*)header_buff;

    skb_pull(skb, buff_len);

    // 复制备份扩展报头的内容
    extended_header = (LABEL_HEADER*)skb->data;
    skb_pull(skb, sizeof(LABEL_HEADER));

    // 恢复备份的报头数据，40 字节表示 ALH 之前只有基本报头，48字节表示还有分片头（现在只有能力考虑这两种情况）
    if(buff_len == 40) {
        ipv6_header->nexthdr = extended_header->next_header;
    }
    else if(buff_len == 48) {
        memcpy(ipv6_header + 1, &(extended_header->next_header), 1);
    }
    else
        printk("Other headers should be processed");

    payload_len = ntohs(ipv6_header->payload_len);
    payload_len -= sizeof(LABEL_HEADER);
    ipv6_header->payload_len = htons(payload_len);
    memcpy(skb_push(skb, buff_len), header_buff, buff_len);
    skb_reset_network_header(skb);
    
    return IPPROTO_LABEL;
}
