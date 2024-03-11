#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>

#include "extended_header.h"
#include "hash_table.h"
#include "kern_aes.h"
#include "kern_ioctl.h"
#include "channel.h"

int input_init(void);
void input_exit(void);
