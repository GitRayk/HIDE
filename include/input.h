#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>

#include "extended_header.h"
#include "kern_aes.h"

int input_init(void);
void input_exit(void);
