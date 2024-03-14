#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/neighbour.h>
#include <net/ip6_route.h>
#include <linux/netdevice.h>

#include "extended_header.h"
#include "kern_aes.h"
#include "kern_ioctl.h"
#include "channel.h"

int output_init(void);
void output_exit(void);
