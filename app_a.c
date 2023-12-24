#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include "ioctl_cmd.h"

int main() {
    int fd;
    IOCTL_CMD   cmd;
    SET_MYSELF_MES kmesg = {
        .aid = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0a},
        .sn = 1
    };

    SET_KEY_MES kmesg_b = {
        .sn = 2,
        .mac = {0x00, 0x0c, 0x29, 0xc2, 0x86, 0x18},
        .aes_key = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18},
        .ip6 = {0x20, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                    ,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
        .aid = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0b}
    };

    // 打开字符设备文件发送命令
    fd = open(CMD_DEV_PATH, O_RDONLY);
    if(fd <= 0) {
        printf("Open cmd device error\n");
        return -1;
    }
    
    cmd.type = IOCTL_SET_MYSELF;
    cmd.buff = &kmesg;
    ioctl(fd, IOCTL_DEV_LABEL, &cmd);

    cmd.type = IOCTL_SET_AES_KEY;
    cmd.buff = &kmesg_b;
    ioctl(fd, IOCTL_DEV_LABEL, &cmd);

    printf("Terminal registers successfully\n");
    return 0;
}