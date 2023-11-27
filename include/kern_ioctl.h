#include <linux/fs.h>
#include <linux/uaccess.h>

#ifndef __KERN_IOCTL__
#define __KERN_IOCTL__

#define CMD_MAJOR 168
#define CMD_DEV_NAME "labelCmd"

enum  CMD_TYPE {
    IOCTL_SET_AID = 1,
    IOCTL_SET_SN,
    IOCTL_SET_AES_KEY
};

// 用户空间和内核模块交互的信息格式
typedef struct ioctl_cmd {
    unsigned int type;
    void* buff;
} IOCTL_CMD;
#endif

int ioctl_init(void);
void ioctl_exit(void);

int kern_cmd_open(struct inode *inode, struct file *file);
int kern_cmd_close(struct inode *inode,struct file *file);

long get_unlocked_ioctl (struct file *filep, unsigned int cmd, unsigned long args);

void get_aid(void *aid);
void get_sn(void *sequence);
void get_aes_key(void *key);