#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>

#ifndef __HASH_TABLE__
#define __HASH_TABLE__
#define HASHTABLE_SIZE 10

// 由 MAC 地址映射到加密密钥
typedef struct __terminal__encrypt_info {
    union {
        char key[6];
        char mac[6];
    };
    char encrypt_key[16];
    // 是否需要时间戳用来表示密钥过期？

    struct hlist_node hnode;
} TERMINAL_ENCRYPT_INFO;

// 由解密出的设备 AID 映射到真实的 IPv6 地址
typedef struct __terminal_ip_info {
    union {
        char key[8];
        char aid[8];
    };
    char ip6[16];
    unsigned int sn;
    
    struct hlist_node hnode;
} TERMINAL_IP_INFO;

// 由真实的 IPv6 地址映射到 aid 和 sn，这个表需要与 TERMINAL_IP_INFO 保持数据一致性
typedef struct __terminal_aid_info {
    union {
        char key[16];
        char ip6[16];
    };
    char aid[8];
    unsigned int sn;

    struct hlist_node hnode;
} TERMINAL_AID_INFO;
#endif

// 将 mac 和 加密密钥 的映射关系存储到哈希表中。成功时返回 0，否则返回负值
int insert_terminal_encrypt_info(const char *mac, const char *encrypt_key);   

// 更新哈希表中指定 mac 的加密密钥
int update_terminal_encrypt_info(const char *mac, const char *encrypt_key);

// 删除哈希表中指定 mac 的表项
int delete_terminal_encrypt_info(const char *mac);

// 根据指定的 mac 地址返回对应的加密密钥
const TERMINAL_ENCRYPT_INFO *find_terminal_of_mac(const char *mac);  

// 清空哈希表中所有信息
void terminal_encrypt_info_clear(void);     

// 同上，提供对 TERMINAL_IP_INFO 哈希表的增删改查接口
int insert_terminal_ip_info(const char *aid, const char *ip6, unsigned int sn);   
int update_terminal_ip_info(const char *aid, const char *ip6, unsigned int sn);
int delete_terminal_ip_info(const char *aid);
const TERMINAL_IP_INFO *find_terminal_of_aid(const char *aid);  
void terminal_ip_info_clear(void);   

// 同上，提供对 TERMINAL_AID_INFO 哈希表的增删改查接口
int insert_terminal_aid_info(const char *ip6, const char *aid, unsigned int sn);   
int update_terminal_aid_info(const char *ip6, const char *aid, unsigned int sn);
int delete_terminal_aid_info(const char *ip6);
const TERMINAL_AID_INFO *find_terminal_of_ip6(const char *ip6);  
void terminal_aid_info_clear(void);   
