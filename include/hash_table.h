#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>

#ifndef __HASH_TABLE__
#define __HASH_TABLE__
#define HASHTABLE_SIZE 10
#define HASH_KEY_LENGTH 6

typedef struct __terminal_info {
    union {
        char key[HASH_KEY_LENGTH];
        char mac[6];
    };
    char encrypt_key[16];
    unsigned int sn;
    // 是否需要时间戳用来表示密钥过期？

    struct hlist_node hnode;
} TERMINAL_INFO;
#endif

// 将 mac 和 加密密钥 的映射关系存储到哈希表中。成功时返回 0，否则返回负值
int insert_terminal_info(const char *mac, const char *encrypt_key, unsigned int sn);   

// 更新哈希表中指定 mac 的加密密钥
int update_terminal_info(const char *mac, const char *encrypt_key, unsigned int sn);

// 删除哈希表中指定 mac 的表项
int delete_terminal_info(const char *mac);

// 根据指定的 mac 地址返回对应的加密密钥
const TERMINAL_INFO *find_terminal_of_mac(const char *mac);  

// 清空哈希表中所有信息
void terminal_info_clear(void);     
