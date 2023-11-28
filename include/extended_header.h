#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>

#ifndef IPPROTO_LABEL
#define IPPROTO_LABEL 253
#define ETH_ADDRESS_LEN 6
#define IPV6_HEADER_LEN 40

// 自定义扩展报头结构
#pragma pack(1)
typedef struct __label_header {
    __u8 next_header;
    __u16 length;
    __u8 reserved;
    __u32 timestamp;
    __u32 sequence;
    __u8 eea[8];
    // 这是基本结构，后续还需要在这个扩展报头后面加一个变长的 IPC (Identity Protection Code)（为什么是变长的？）
} LABEL_HEADER;
#pragma pack()
#endif

int add_extended_header(struct sk_buff *skb, unsigned int ts, unsigned sn, const unsigned char *eea);
int remove_extended_header(struct sk_buff *skb);

