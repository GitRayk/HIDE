#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/ktime.h>

#define ENCRYPT_SIZE 16     // 加密长度为 128 位

int aes_encrypt(const char* aid, const char *ts, const char *sn, const char* aes_key, char* target);
int aes_init(void);
void aes_exit(void);
