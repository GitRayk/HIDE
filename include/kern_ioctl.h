#include <linux/fs.h>
#include <linux/uaccess.h>

#include "ioctl_cmd.h"
#include "hash_table.h"

int ioctl_init(void);
void ioctl_exit(void);

int kern_cmd_open(struct inode *inode, struct file *file);
int kern_cmd_close(struct inode *inode,struct file *file);

ssize_t kern_cmd_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos);
long get_unlocked_ioctl (struct file *filep, unsigned int cmd, unsigned long args);