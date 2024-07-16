#include "kern_aes.h"

// struct crypto_cipher *tfm = NULL;

int aes_init(void) {
    // 创建 AES 加密时使用的相关上下文
    /*
    tfm = crypto_alloc_cipher("aes", 0, 0);
    if(IS_ERR(tfm)) {
        printk(KERN_ERR "Failed to load AES cipher\n");
        return PTR_ERR(tfm);
    }
    */
    return 0;
}

void aes_exit(void) {
/*    
    if (tfm != NULL)
    	crypto_free_cipher(tfm);
*/
}

// 将指定信息拼接并进行AES加密，加密结果保存在 target 指向的地址当中
int aes_encrypt(const char* aid, const char *ts, const char *sn, struct crypto_cipher *tfm, char* target) {
    char plaintext[ENCRYPT_SIZE] = {0};
    s64 t1 = ktime_to_ns(ktime_get());
    
    // 拼接 AID、TS、SN
    memcpy(plaintext, aid, 8);
    memcpy(plaintext + 8,  ts, 4);
    memcpy(plaintext + 12, sn, 4);

    printk("加密[数据复制时间]: %lld\n", ktime_to_ns(ktime_get()) - t1);
/*
    // 加载加解密时所需要使用的密钥
    if(crypto_cipher_setkey(tfm, aes_key, ENCRYPT_SIZE)) {
        printk(KERN_ERR "Failed to set AES key\n");
        crypto_free_cipher(tfm);
        return -1;
    }  

    printk("加密[设置加密密钥时间]: %lld\n", ktime_to_ns(ktime_get()) - t1);
*/
    // 对明文进行加密，加密结果保存在指定地址
    crypto_cipher_encrypt_one(tfm, target, plaintext);

    printk("加密[加密时间]: %lld\n", ktime_to_ns(ktime_get()) - t1);

    return 0;
}

int aes_decrypt(struct crypto_cipher *tfm, const char *IID, const char *EEA, char *target) {
    s64 t1 = ktime_to_ns(ktime_get());
    char decrypt_text[ENCRYPT_SIZE] = {0};
    memcpy(decrypt_text, IID, 8);
    memcpy(decrypt_text + 8, EEA, 8);

    printk("解密[数据复制时间]: %lld\n", ktime_to_ns(ktime_get()) - t1);
/*
    // 加载加解密时所需要使用的密钥
    if(crypto_cipher_setkey(tfm, aes_key, ENCRYPT_SIZE)) {
        printk(KERN_ERR "Failed to set AES key\n");
        crypto_free_cipher(tfm);
        return -1;
    }

    printk("解密[设置解密密钥时间]: %lld\n", ktime_to_ns(ktime_get()) - t1);
*/
    crypto_cipher_decrypt_one(tfm, target, decrypt_text);

    printk("解密[解密时间]: %lld\n", ktime_to_ns(ktime_get()) - t1);
    return 0;
}