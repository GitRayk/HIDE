#include "output.h"

unsigned int hook_output(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    add_extended_header(skb);

    return NF_ACCEPT;
}

static struct nf_hook_ops nfho = {
    .hook = hook_output,
    .pf = PF_INET6,
    .hooknum = NF_INET_POST_ROUTING,
    .priority = NF_IP6_PRI_FIRST
};

int output_init(void) {
    nf_register_net_hook(&init_net, &nfho);
    return 0;
}

void output_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
}
    
    
    
