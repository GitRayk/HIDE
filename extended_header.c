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

int add_extended_header(struct sk_buff *skb, unsigned int ts, unsigned sn, const unsigned char *eea) {
    struct ipv6hdr ipv6_header;
    LABEL_HEADER *extended_header = NULL;
    short payload_len;

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
    strncpy(extended_header->eea, eea, 8);

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

int remove_extended_header(struct sk_buff *skb) {
    struct ipv6hdr ipv6_header;
    LABEL_HEADER *extended_header = NULL;
    short payload_len;
    skb->transport_header += sizeof(LABEL_HEADER);

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

    // debug_print_packet(skb);
    
    return IPPROTO_LABEL;
}
