#include "channel.h"
#include "hash_table.h"

struct sock *netlink_sock;
static unsigned int app_pid;

static void receive_msg(struct sk_buff *skb) {
    //理论上只在用户空间的应用程序启动时会发送消息，以此确定进程号。后续的消息由内核主动向用户空间发出，并单方向通信即可
    if(app_pid == 0) {
        app_pid = nlmsg_hdr(skb)->nlmsg_pid;
        printk("Set user process id successfully");
    }
}

struct netlink_kernel_cfg cfg = {
        .input = receive_msg
};

int channel_init(void) {
    netlink_sock = NULL;
    app_pid = 0;

    netlink_sock =  netlink_kernel_create(&init_net, NETLINK_USERSOCK, &cfg);
    return 0;
}
void channel_exit(void) {
    if(netlink_sock)    netlink_kernel_release(netlink_sock);
}

void channel_send(unsigned int type, char *mesg, unsigned int mesg_len) {
    CHANNEL_MES data;
    data.type = type;
    memcpy((&data.type)+1, mesg, mesg_len);

    if(app_pid != 0) {
    struct sk_buff *skb_out = nlmsg_new(sizeof(CHANNEL_MES), 0);
    struct nlmsghdr *nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, sizeof(CHANNEL_MES), 0);
    NETLINK_CB(skb_out).dst_group = 0;
    memcpy((char*)(nlh + 1), &data, sizeof(CHANNEL_MES));

    nlmsg_unicast(netlink_sock, skb_out, app_pid);
    }
}

void set_upload_mes(UPLOAD_MES *mesg, struct sk_buff *skb, const struct nf_hook_state *state, unsigned char *aid, unsigned int delayTime, const char *states, const char *notes) {
    struct net_device *dev;
    struct in6_addr net_device_ip, saddr, daddr;
    const TERMINAL_AID_INFO *aid_info = NULL;
    char *char_addr = (char*)&(ipv6_hdr(skb)->saddr);

    memset((char*)mesg, 0, sizeof(UPLOAD_MES));
    dev = state->in;
    daddr = ipv6_hdr(skb)->daddr;
    saddr = ipv6_hdr(skb)->saddr;
    if (ipv6_dev_get_saddr(&init_net, dev, &daddr, 0, &net_device_ip) != 0) {
        printk("Can't find net device [%s]ipv6 to %pI6", dev->name, &daddr);
        memset(mesg->source, 0, 8);
    } 
    else {
        aid_info = find_terminal_of_ip6((char*)&net_device_ip);     // 获取当前网卡的自身的 aid
        if(aid_info == NULL) {
            printk("Can't get aid of ipv6: %pI6", &net_device_ip);
            memset(mesg->source, 0, 8);
        }
        else {
            memcpy(mesg->source, aid_info->aid, 8);
        }
    }

    memcpy(mesg->label, char_addr, 16);
    memcpy(mesg->aid, aid, 8);
    strncpy(mesg->states, states, 8);
    strncpy(mesg->notes, notes, 24);
    mesg->delayTime = delayTime;
}