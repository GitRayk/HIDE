#include <linux/netlink.h>
#include <net/sock.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>

#include "channel_mes.h"

int channel_init(void);
void channel_exit(void);

void channel_send(unsigned int type, char *mesg, unsigned int mesg_len);
void set_upload_mes(UPLOAD_MES *mesg, struct sk_buff *skb, const struct nf_hook_state *state, unsigned char *aid, unsigned int delayTime, const char *states, const char *notes);