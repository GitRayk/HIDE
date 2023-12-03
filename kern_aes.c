#include "kern_aes.h"

struct crypto_cipher *tfm = NULL;

int aes_init(void) {
    // 创建 AES 加密时使用的相关上下文
    tfm = crypto_alloc_cipher("aes", 0, 0);
    if(IS_ERR(tfm)) {
        printk(KERN_ERR "Failed to load AES cipher\n");
        return PTR_ERR(tfm);
    }
    return 0;
}

void aes_exit(void) {
    if (tfm != NULL)
    	crypto_free_cipher(tfm);
}

// 将指定信息拼接并进行AES加密，加密结果保存在 target 指向的地址当中
int aes_encrypt(const char* aid, const char *ts, const char *sn, const char* aes_key, char* target) {
    char plaintext[ENCRYPT_SIZE] = {0};
    char decrypt_text[ENCRYPT_SIZE] = {0};

    s64 start_time = ktime_to_ns(ktime_get());
    
    // 拼接 AID、TS、SN
    memcpy(plaintext, aid, 8);
    memcpy(plaintext + 8,  ts, 4);
    memcpy(plaintext + 12, sn, 4);

    s64 copy_time = ktime_to_ns(ktime_get());

    // 加载加解密时所需要使用的密钥
    if(crypto_cipher_setkey(tfm, aes_key, ENCRYPT_SIZE)) {
        printk(KERN_ERR "Failed to set AES key\n");
        crypto_free_cipher(tfm);
        return -1;
    }

    s64 setkey_time = ktime_to_ns(ktime_get());

    // 对明文进行加密，加密结果保存在指定地址
    crypto_cipher_encrypt_one(tfm, target, plaintext);

    s64 encrypt_time = ktime_to_ns(ktime_get());

    // 测试解密过程的时间
    crypto_cipher_decrypt_one(tfm, decrypt_text, target);
    s64 decrypt_time = ktime_to_ns(ktime_get());
    if(strncmp(plaintext, decrypt_text, ENCRYPT_SIZE) != 0)
        printk("Decrypt error");

    printk("//////////////// debug:");
    printk("sn: %d, aid: %s, aes_key: %s", *sn, aid, aes_key);
    printk("copy_time: %lld ns", copy_time - start_time);
    printk("setkey_time: %lld ns", setkey_time - copy_time);
    printk("encrypt_time: %lld ns", encrypt_time - setkey_time);
    printk("decrypt_time: %lld ns", decrypt_time - encrypt_time);

    return 0;
}

int aes_decrypt(const char *aes_key, const char *IID, const char *EEA, char *target) {
    char decrypt_text[ENCRYPT_SIZE] = {0};
    memcpy(decrypt_text, IID, 8);
    memcpy(decrypt_text, EEA, 8);

    // 加载加解密时所需要使用的密钥
    if(crypto_cipher_setkey(tfm, aes_key, ENCRYPT_SIZE)) {
        printk(KERN_ERR "Failed to set AES key\n");
        crypto_free_cipher(tfm);
        return -1;
    }

    crypto_cipher_decrypt_one(tfm, decrypt_text, target);
    return 0;
}