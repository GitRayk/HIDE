#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <crypto/hash.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>

int kern_hash_init(void);
void kern_hash_exit(void);
int get_hash(const char *plaintext, unsigned int len, char *target);

int get_digest_size(void);