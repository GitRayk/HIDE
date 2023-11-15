#include "input.h"

unsigned int hook_input(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    remove_extended_header(skb);

    return NF_ACCEPT;
}

static struct nf_hook_ops nfho = {
    .hook = hook_input,
    .pf = PF_INET6,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP6_PRI_FIRST
};

int input_init(void) {
    nf_register_net_hook(&init_net, &nfho);
    return 0;
}

void input_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
}
    
    
    
