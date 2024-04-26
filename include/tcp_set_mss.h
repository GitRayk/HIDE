#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#ifndef __TCP_SET_MSS__
#define __TCP_SET_MSS__

#define MSS_DECREASE_AMOUNT 52

#endif

int tcp_set_mss_init(void);
void tcp_set_mss_exit(void);