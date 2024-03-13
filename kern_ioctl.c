#include "kern_ioctl.h"

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
    // 当程序试图读取该设备文件时，输出提示信息
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

    info = tips;
    info_len = strlen(tips);
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
    SET_AID_MES buff_aid;
    memset(&iocmd, 0, sizeof(IOCTL_CMD));

    //获取用户空间的命令参数，并根据命令做具体的操作
    copy_from_user((char*)&iocmd, (char*)args, sizeof(iocmd));

    if(iocmd.type == IOCTL_SET_AES_KEY) {
        copy_from_user((char*)&buff, (char*)iocmd.buff, sizeof(SET_KEY_MES));
        if(find_terminal_of_mac(buff.mac) == NULL)
            insert_terminal_encrypt_info(buff.mac, buff.aes_key);
        else
            update_terminal_encrypt_info(buff.mac, buff.aes_key);
    }
    else if(iocmd.type == IOCTL_SET_AID) {
        copy_from_user((char*)&buff_aid, (char*)iocmd.buff, sizeof(SET_AID_MES));
        if(find_terminal_of_aid(buff_aid.aid) == NULL)
            insert_terminal_ip_info(buff_aid.aid, buff_aid.ip6, buff_aid.sn);
        else
            update_terminal_ip_info(buff_aid.aid, buff_aid.ip6, buff_aid.sn);

        if(find_terminal_of_ip6(buff_aid.ip6) == NULL)
            insert_terminal_aid_info(buff_aid.ip6, buff_aid.aid, buff_aid.sn);
        else
            update_terminal_aid_info(buff_aid.ip6, buff_aid.aid, buff_aid.sn);
    }
    else {
        printk("Error ioctl type: %d", iocmd.type);
        return -1;
    }
    return 0;
}