#include "hash_table.h"

DEFINE_HASHTABLE(terminal_encrypt_info_hashtable, HASHTABLE_SIZE);
DEFINE_HASHTABLE(terminal_ip_info_hashtable, HASHTABLE_SIZE);
DEFINE_HASHTABLE(terminal_aid_info_hashtable, HASHTABLE_SIZE);

TERMINAL_ENCRYPT_INFO *fake_terminal;
void hashtable_init(void) {
    unsigned char aes_key[16] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    fake_terminal = kmalloc(sizeof(TERMINAL_ENCRYPT_INFO), GFP_KERNEL);
    fake_terminal->tfm = crypto_alloc_cipher("aes", 0, 0);
    crypto_cipher_setkey(fake_terminal->tfm, aes_key, 16);
}

TERMINAL_ENCRYPT_INFO  *get_fake_terminal_encrypt_info(void) {
    return fake_terminal;
}

void hashtable_exit(void) {
    terminal_encrypt_info_clear();
    terminal_ip_info_clear();
    terminal_aid_info_clear();
}

int insert_terminal_encrypt_info(const char *mac, const struct crypto_cipher *tfm) {
    TERMINAL_ENCRYPT_INFO *tinfo = kmalloc(sizeof(TERMINAL_ENCRYPT_INFO), GFP_KERNEL);
    memcpy(tinfo->mac, mac, 6);
    tinfo->tfm = tfm;
    
    // 由于 hash_add 并不会检查是否已经有 key 对应的表项，以防调用 insert 时造成覆盖，这里作一次检查，使功能与 update 区分开
    if (find_terminal_of_mac(mac) != NULL)
        return -1;
    
    // 哈希表的 key 不能为字符串，所以利用 jhash 将实际的 key (mac) 映射成一个数字
    hash_add(terminal_encrypt_info_hashtable, &tinfo->hnode, jhash(tinfo->mac, 6, 0));
    return 0;
}

int update_terminal_encrypt_info(const char *mac, const struct crypto_cipher *tfm) {
    TERMINAL_ENCRYPT_INFO *tinfo = NULL;
    hash_for_each_possible(terminal_encrypt_info_hashtable, tinfo, hnode, jhash(mac, 6, 0)) {
        tinfo->tfm = tfm;
        return 0;
    }
    return -1;
}

int delete_terminal_encrypt_info(const char *mac) {
    TERMINAL_ENCRYPT_INFO *tinfo = NULL;
    hash_for_each_possible(terminal_encrypt_info_hashtable, tinfo, hnode, jhash(mac, 6, 0)) {
        hash_del(&(tinfo->hnode));
        kfree(tinfo);
        return 0;
    }
    return -1;
}

const TERMINAL_ENCRYPT_INFO *find_terminal_of_mac(const char *mac) {
    TERMINAL_ENCRYPT_INFO *tinfo = NULL;
    hash_for_each_possible(terminal_encrypt_info_hashtable, tinfo, hnode, jhash(mac, 6, 0)) {
        return tinfo;
    }
    return NULL;
}

void terminal_encrypt_info_clear(void) {
    TERMINAL_ENCRYPT_INFO *tinfo = NULL;
    int i;

    hash_for_each(terminal_encrypt_info_hashtable, i, tinfo, hnode) {
        hash_del(&(tinfo->hnode));
        crypto_free_cipher(tinfo->tfm);
        kfree(tinfo);
    }
}

// **** TERNIMAL_IP_INFO_HASHTABLE *********

int insert_terminal_ip_info(const char *aid, const char *ip6, unsigned int sn) {
    TERMINAL_IP_INFO *tinfo = kmalloc(sizeof(TERMINAL_IP_INFO), GFP_KERNEL);
    memcpy(tinfo->aid, aid, 8);
    memcpy(tinfo->ip6, ip6, 16);
    tinfo->sn = sn;
    
    // 由于 hash_add 并不会检查是否已经有 key 对应的表项，以防调用 insert 时造成覆盖，这里作一次检查，使功能与 update 区分开
    if (find_terminal_of_aid(aid) != NULL)
        return -1;
    
    // 哈希表的 key 不能为字符串，所以利用 jhash 将实际的 key (mac) 映射成一个数字
    hash_add(terminal_ip_info_hashtable, &tinfo->hnode, jhash(tinfo->aid, 8, 0));
    return 0;
}

int update_terminal_ip_info(const char *aid, const char *ip6, unsigned int sn) {
    TERMINAL_IP_INFO *tinfo = NULL;
    hash_for_each_possible(terminal_ip_info_hashtable, tinfo, hnode, jhash(aid, 8, 0)) {
        memcpy(tinfo->ip6, ip6, 16);
        tinfo->sn = sn;
        return 0;
    }
    return -1;
}

int delete_terminal_ip_info(const char *aid) {
    TERMINAL_IP_INFO *tinfo = NULL;
    hash_for_each_possible(terminal_ip_info_hashtable, tinfo, hnode, jhash(aid, 8, 0)) {
        hash_del(&(tinfo->hnode));
        kfree(tinfo);
        return 0;
    }
    return -1;
}

const TERMINAL_IP_INFO *find_terminal_of_aid(const char *aid) {
    TERMINAL_IP_INFO *tinfo = NULL;
    hash_for_each_possible(terminal_ip_info_hashtable, tinfo, hnode, jhash(aid, 8, 0)) {
        return tinfo;
    }
    return NULL;
}

void terminal_ip_info_clear(void) {
    TERMINAL_IP_INFO *tinfo = NULL;
    int i;

    hash_for_each(terminal_ip_info_hashtable, i, tinfo, hnode) {
        hash_del(&(tinfo->hnode));
        kfree(tinfo);
    }
}


// **** TERNIMAL_AID_INFO_HASHTABLE *********

int insert_terminal_aid_info(const char *ip6, const char *aid, unsigned int sn) {
    TERMINAL_AID_INFO *tinfo = kmalloc(sizeof(TERMINAL_AID_INFO), GFP_KERNEL);
    memcpy(tinfo->aid, aid, 8);
    memcpy(tinfo->ip6, ip6, 16);
    tinfo->sn = sn;
    
    // 由于 hash_add 并不会检查是否已经有 key 对应的表项，以防调用 insert 时造成覆盖，这里作一次检查，使功能与 update 区分开
    if (find_terminal_of_ip6(ip6) != NULL)
        return -1;
    
    // 哈希表的 key 不能为字符串，所以利用 jhash 将实际的 key (mac) 映射成一个数字
    hash_add(terminal_aid_info_hashtable, &tinfo->hnode, jhash(tinfo->ip6, 16, 0));
    return 0;
}

int update_terminal_aid_info(const char *ip6, const char *aid, unsigned int sn) {
    TERMINAL_AID_INFO *tinfo = NULL;
    hash_for_each_possible(terminal_aid_info_hashtable, tinfo, hnode, jhash(ip6, 16, 0)) {
        memcpy(tinfo->aid, aid, 8);
        tinfo->sn = sn;
        return 0;
    }
    return -1;
}

int delete_terminal_aid_info(const char *ip6) {
    TERMINAL_AID_INFO *tinfo = NULL;
    hash_for_each_possible(terminal_aid_info_hashtable, tinfo, hnode, jhash(ip6, 16, 0)) {
        hash_del(&(tinfo->hnode));
        kfree(tinfo);
        return 0;
    }
    return -1;
}

const TERMINAL_AID_INFO *find_terminal_of_ip6(const char *ip6) {
    TERMINAL_AID_INFO *tinfo = NULL;
    hash_for_each_possible(terminal_aid_info_hashtable, tinfo, hnode, jhash(ip6, 16, 0)) {
        return tinfo;
    }
    return NULL;
}

void terminal_aid_info_clear(void) {
    TERMINAL_AID_INFO *tinfo = NULL;
    int i;

    hash_for_each(terminal_aid_info_hashtable, i, tinfo, hnode) {
        hash_del(&(tinfo->hnode));
        kfree(tinfo);
    }
}
