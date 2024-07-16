#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/ktime.h>

#define ENCRYPT_SIZE 16     // 加密长度为 128 位

int aes_encrypt(const char* aid, const char *ts, const char *sn, struct crypto_cipher *tfm, char* target);
int aes_decrypt(struct crypto_cipher *tfm, const char *IID, const char *EEA, char *target);
int aes_init(void);
void aes_exit(void);
