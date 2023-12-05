#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include "kern_hash.h"

#ifndef IPPROTO_LABEL
#define IPPROTO_LABEL 253
#define ETH_ADDRESS_LEN 6
#define IPV6_ADDRESS_LEN 16
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
    __u8 IPC[32];
    // 本 demo 中使用 aes 加密、sha256 作哈希，故 eea 长为 64位，IPC 长为 256 位
} LABEL_HEADER;
#pragma pack()
#endif

// 返回 skb 中的地址标签扩展报头，当此报头不存在时返回 NULL
LABEL_HEADER *skb_label_header(struct sk_buff *skb);

int add_extended_header(struct sk_buff *skb, const char *AID, unsigned int ts, unsigned sn, const unsigned char *eea);
int remove_extended_header(struct sk_buff *skb, const char *AID);

