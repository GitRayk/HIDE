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

int add_extended_header(struct sk_buff *skb) {
    struct ipv6hdr ipv6_header;
    struct my_extension_header *extended_header = NULL;
    struct icmp6hdr *icmpv6h = icmp6_hdr(skb);
    short payload_len;

    // 复制备份原IPv6基本报头然后将其移除
    pskb_expand_head(skb, IPV6_HEADER_LEN, 0, GFP_ATOMATIC)
    memcpy(&ipv6_header, skb->data, IPV6_HEADER_LEN);
    skb_pull(skb, IPV6_HEADER_LEN);

    // 创建自定义扩展报头
    extended_header = skb_push(skb, sizeof(struct my_extension_header));
    extended_header->next_header = ipv6_header.nexthdr;
    extended_header->length = 0;
    extended_header->checksum = icmpv6h->icmp6_cksum; 

    // 恢复IPv6基本报头
    ipv6_header.nexthdr = IPPROTO_LABEL;
    payload_len = ntohs(ipv6_header.payload_len);
    payload_len += sizeof(struct my_extension_header);
    ipv6_header.payload_len = htons(payload_len);

    memcpy(skb_push(skb, IPV6_HEADER_LEN), &ipv6_header, sizeof(struct ipv6hdr));
    // skb->network_header -= sizeof(struct my_extension_header);
    skb_reset_network_header(skb);
    skb_reset_mac_header(skb);
    
    return 0;
}

int remove_extended_header(struct sk_buff *skb) {
    struct ipv6hdr ipv6_header;
    struct my_extension_header *extended_header = NULL;
    short payload_len;

    // 复制备份原IPv6基本报头
    memcpy(&ipv6_header, skb->data, IPV6_HEADER_LEN);
    if(ipv6_header.nexthdr != IPPROTO_LABEL)
	return ipv6_header.nexthdr;

    skb_pull(skb, IPV6_HEADER_LEN);

    // 复制备份扩展报头的内容
    extended_header = (struct my_extension_header*)skb->data;
    skb_pull(skb, sizeof(struct my_extension_header));

    // 恢复IPv6基本报头
    ipv6_header.nexthdr = extended_header->next_header;
    payload_len = ntohs(ipv6_header.payload_len);
    payload_len -= sizeof(struct my_extension_header);
    ipv6_header.payload_len = htons(payload_len);

    memcpy(skb_push(skb, IPV6_HEADER_LEN), &ipv6_header, sizeof(struct ipv6hdr));
    // skb->network_header += sizeof(struct my_extension_header);
    skb_reset_network_header(skb);
    skb_reset_mac_header(skb);

    // debug_print_packet(skb);
    
    return IPPROTO_LABEL;
}
