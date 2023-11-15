#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>

#ifndef IPPROTO_LABEL
#define IPPROTO_LABEL 253
#define ETH_ADDRESS_LEN 6
#define IPV6_HEADER_LEN 40

// 自定义扩展报头结构
struct my_extension_header {
    uint8_t next_header;
    uint8_t length;
    uint16_t checksum;
    // 添加其他字段或数据
};
#endif

int add_extended_header(struct sk_buff *skb);
int remove_extended_header(struct sk_buff *skb);

