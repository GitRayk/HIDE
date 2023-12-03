#include "hash_table.h"

DEFINE_HASHTABLE(terminal_info_hashtable, HASHTABLE_SIZE);

int insert_terminal_info(const char *mac, const char *encrypt_key, unsigned int sn) {
    TERMINAL_INFO *tinfo = kmalloc(sizeof(TERMINAL_INFO), GFP_KERNEL);
    strncpy(tinfo->mac, mac, HASH_KEY_LENGTH);
    strncpy(tinfo->encrypt_key, encrypt_key, 16);
    tinfo->sn = sn;
    
    // 由于 hash_add 并不会检查是否已经有 key 对应的表项，以防调用 insert 时造成覆盖，这里作一次检查，使功能与 update 区分开
    if (find_terminal_of_mac(mac) != NULL)
        return -1;
    
    // 哈希表的 key 不能为字符串，所以利用 jhash 将实际的 key (mac) 映射成一个数字
    hash_add(terminal_info_hashtable, &tinfo->hnode, jhash(tinfo->mac, HASH_KEY_LENGTH, 0));
    return 0;
}

int update_terminal_info(const char *mac, const char *encrypt_key, unsigned int sn) {
    TERMINAL_INFO *tinfo = NULL;
    hash_for_each_possible(terminal_info_hashtable, tinfo, hnode, jhash(mac, HASH_KEY_LENGTH, 0)) {
        strncpy(tinfo->encrypt_key, encrypt_key, 16);
        tinfo->sn = sn;
        return 0;
    }
    return -1;
}

int delete_terminal_info(const char *mac) {
    TERMINAL_INFO *tinfo = NULL;
    hash_for_each_possible(terminal_info_hashtable, tinfo, hnode, jhash(mac, HASH_KEY_LENGTH, 0)) {
        hash_del(&(tinfo->hnode));
        kfree(tinfo);
        return 0;
    }
    return -1;
}

const TERMINAL_INFO *find_terminal_of_mac(const char *mac) {
    TERMINAL_INFO *tinfo = NULL;
    hash_for_each_possible(terminal_info_hashtable, tinfo, hnode, jhash(mac, HASH_KEY_LENGTH, 0)) {
        return tinfo;
    }
    return NULL;
}

void terminal_info_clear(void) {
    TERMINAL_INFO *tinfo = NULL;
    int i;

    hash_for_each(terminal_info_hashtable, i, tinfo, hnode) {
        hash_del(&(tinfo->hnode));
        kfree(tinfo);
    }
}
