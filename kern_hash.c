#include "kern_hash.h"

static struct crypto_shash *hash_tfm = NULL;
static struct shash_desc *hash_desc = NULL;

int kern_hash_init(void) {
    hash_tfm = crypto_alloc_shash("sha256", 0, 0);
    if(IS_ERR(hash_tfm)) {
        pr_err("Error allocating hash transform");
        return -1;
    }
    hash_desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(hash_tfm), GFP_KERNEL);
    if(!hash_desc) {
        crypto_free_shash(hash_tfm);
        pr_err("Error allocating hash_desc");
        return -1;
    }
    hash_desc->tfm = hash_tfm;

    return 0; 
}

void kern_hash_exit(void) {
    if(hash_tfm != NULL)    crypto_free_shash(hash_tfm);
    if(hash_desc != NULL)   kfree(hash_desc);
}

int get_hash(const char *plaintext, unsigned int len, char *target) {
    return crypto_shash_digest(hash_desc, plaintext, len, target);
}

int get_digest_size(void) {
    return crypto_shash_digestsize(hash_tfm);
}