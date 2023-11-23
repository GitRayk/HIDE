#include "output.h"

static void set_ether(struct sk_buff *skb) {
    unsigned char hw[6];
    memset(hw, 0xFF, 6);
    eth_header(skb, skb->dev, ETH_P_IP, hw, NULL, 0);
}

unsigned int hook_output(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    add_extended_header(skb);
    set_ether(skb);
    dev_queue_xmit(skb);

    return NF_STOLEN;
}

static struct nf_hook_ops nfho = {
    .hook = hook_output,
    .pf = NFPROTO_IPV6,
    .hooknum = NF_INET_POST_ROUTING,
    .priority = NF_IP6_PRI_LAST
};

int output_init(void) {
    nf_register_net_hook(&init_net, &nfho);
    return 0;
}

void output_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
}
    
    
    
