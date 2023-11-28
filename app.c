#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "ioctl_cmd.h"

int main() {
    unsigned int sn;
    char AID[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    char aes_key[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
    };
    int fd;
    IOCTL_CMD   cmd;

    // 当终端完成注册之后，生成唯一的 sn 和 AID
    srand((unsigned int)time(NULL));
    sn = rand();

    // 打开字符设备文件发送命令
    fd = open(CMD_DEV_PATH, O_RDONLY);
    if(fd <= 0) {
        printf("Open cmd device error\n");
        return -1;
    }
    
    cmd.type = IOCTL_SET_AID;
    cmd.buff = AID;
    ioctl(fd, IOCTL_DEV_LABEL, &cmd);

    cmd.type = IOCTL_SET_SN;
    cmd.buff = &sn;
    ioctl(fd, IOCTL_DEV_LABEL, &cmd);

    cmd.type = IOCTL_SET_AES_KEY;
    cmd.buff = aes_key;
    ioctl(fd, IOCTL_DEV_LABEL, &cmd);

    printf("Terminal registers successfully\n");
    return 0;
}