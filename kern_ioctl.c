#include "kern_ioctl.h"

// 这些数据是本终端的信息
static char __AID[8];
static unsigned int __sn;

static int cmd_major = CMD_MAJOR;

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = kern_cmd_open,
    .release = kern_cmd_close,
    .read = kern_cmd_read,
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

ssize_t kern_cmd_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos) {
    // 当程序试图读取该设备文件时，按 SET_MYSELF_MES 的格式显示该终端的 sn 和 aid
    // 如果内核还没有获取到 sn 和 aid，则显示提示信息
    SET_MYSELF_MES myself_buff;
    static int end_of_info = 0;     // 控制显示信息的长度，当 count 过大时也只可读一次完整的信息
    char tips[] = "No Info\n";
    char*info = NULL;
    int info_len = 0;
    int pos = 0;        // pos 表示当前读取的信息位置

    // 当 end_of_info 为 1 时表示已经完整的读取过一次信息，则返回 0 以终止本次读取，并重置控制变量
    if(end_of_info == 1) {
        end_of_info = 0;
        return 0;
    }

    if(__sn == 0) {
        info = tips;
        info_len = strlen(tips);
    }
    else {
        info = (char *)&myself_buff;
        info_len = sizeof(SET_MYSELF_MES);
    }
    info_len = info_len < count ? info_len : count;

    while(pos < info_len) {
        put_user(*info, buf);
        buf++, info++, pos++;
    }
    end_of_info = 1;
    return info_len;
}

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
            insert_terminal_encrypt_info(buff.mac, buff.aes_key, buff.sn);
        else
            update_terminal_encrypt_info(buff.mac, buff.aes_key, buff.sn);

        if(find_terminal_of_aid(buff.aid) == NULL)
            insert_terminal_ip_info(buff.aid, buff.ip6);
        else
            update_terminal_ip_info(buff.aid, buff.ip6);

        if(find_terminal_of_ip6(buff.ip6) == NULL)
            insert_terminal_aid_info(buff.ip6, buff.aid, buff.sn);
        else
            update_terminal_aid_info(buff.ip6, buff.aid, buff.sn);
    }
    else if (iocmd.type == IOCTL_SET_MYSELF) {
        copy_from_user((char*)&myself_buff, (char*)iocmd.buff, sizeof(SET_MYSELF_MES));
        __sn = myself_buff.sn;
        memcpy(__AID, myself_buff.aid, 8);
    }
    else {
        printk("Error ioctl type: %d", iocmd.type);
        return -1;
    }
    return 0;
}

// aid、sn、aes_key 只能通过 getter 来获取，防止被其他模块修改
void get_aid(void *aid) {
    memcpy((char*)aid, (char*)__AID, 8);
}

void get_sn(void *sequence) {
    memcpy((char*)sequence, (char*)&__sn, sizeof(__sn));
}