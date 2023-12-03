#include "kern_ioctl.h"

// 这些数据是本终端的信息
static char __AID[8];
static unsigned int __sn;
static char __aes_key[16];

static int cmd_major = CMD_MAJOR;

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = kern_cmd_open,
    .release = kern_cmd_close,
    .read = NULL,
    .write = NULL,
    .unlocked_ioctl = get_unlocked_ioctl
};

/* 通过 cmd 来确保对设备文件访问的唯一性 */
static int cmd_open = 0;

int kern_cmd_open(struct inode *inode, struct file *file) {
    if(cmd_open > 0) {
        return -EBUSY;
    }
    cmd_open++;
    return 0;
}

int kern_cmd_close(struct inode *inode,struct file *file) {
    if(cmd_open > 0) {
        cmd_open--;
    }
    return 0;
}

/* 设备的初始化和退出接口 */

int ioctl_init(void) {
    // 注册设备文件，用于与用户空间进行交互
    int ret;

    memset(__AID, 0, 8);
    __sn = 0;
    memset(__aes_key, 0, 16);

    ret = register_chrdev(cmd_major, CMD_DEV_NAME, &fops);
    if(ret < 0) return ret;
    if(ret > 0) cmd_major = ret;

    printk("Register command device successfully.\n");
    return 0;
}

void ioctl_exit(void) {
    unregister_chrdev(cmd_major, CMD_DEV_NAME);
    printk("Unreigster command device successfully.\n");
}


/* 设备实际的业务逻辑函数 */

long get_unlocked_ioctl (struct file *filep, unsigned int cmd, unsigned long args) {
    IOCTL_CMD iocmd;
    SET_KEY_MES buff;
    SET_MYSELF_MES myself_buff;
    memset(&iocmd, 0, sizeof(IOCTL_CMD));

    //获取用户空间的命令参数，并根据命令做具体的操作
    copy_from_user((char*)&iocmd, (char*)args, sizeof(iocmd));

    if(iocmd.type == IOCTL_SET_AES_KEY) {
        copy_from_user((char*)&buff, (char*)iocmd.buff, sizeof(SET_KEY_MES));
        if(find_terminal_of_mac(buff.mac) == NULL)
            insert_terminal_info(buff.mac, buff.aes_key, buff.sn);
        else
            update_terminal_info(buff.mac, buff.aes_key, buff.sn);
    }
    else if (iocmd.type == IOCTL_SET_MYSELF) {
        copy_from_user((char*)&myself_buff, (char*)iocmd.buff, sizeof(SET_MYSELF_MES));
        __sn = myself_buff.sn;
        strncpy(__aes_key, myself_buff.aes_key, 16);
        strncpy(__AID, myself_buff.aid, 8);
    }
    else {
        printk("Error ioctl type: %d", iocmd.type);
        return -1;
    }
    return 0;
}

// aid、sn、aes_key 只能通过 getter 来获取，防止被其他模块修改
void get_aid(void *aid) {
    strncpy((char*)aid, (char*)__AID, 8);
}

void get_sn(void *sequence) {
    strncpy((char*)sequence, (char*)&__sn, sizeof(__sn));
}

void get_aes_key(void *key) {
    strncpy((char*)key, (char*)__aes_key, 16);
}