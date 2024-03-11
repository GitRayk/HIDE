#include <linux/netlink.h>
#include <net/sock.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/netfilter.h>

#ifndef __CHANNEL__
#define __CHANNEL__
typedef  struct __channel_mes {
    unsigned char source[8];
    char states[8];
    unsigned char label[16];
    char notes[16];
    unsigned char aid[8];
    unsigned int delayTime;
} CHANNEL_MES;
#endif

int channel_init(void);
void channel_exit(void);

void channel_send(char *mesg, unsigned int mesg_len);
CHANNEL_MES create_channel_mes(char* source, char* states, char* label, char* notes, char* aid,int delayTime);