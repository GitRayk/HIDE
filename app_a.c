#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include "ioctl_cmd.h"

int main() {
    unsigned int sn = 12;
    char AID[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    char aes_key[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
    };
    int fd;
    IOCTL_CMD   cmd;
    SET_MYSELF_MES kmesg;

    // 打开字符设备文件发送命令
    fd = open(CMD_DEV_PATH, O_RDONLY);
    if(fd <= 0) {
        printf("Open cmd device error\n");
        return -1;
    }
    
    cmd.type = IOCTL_SET_MYSELF;
    memcpy(kmesg.aes_key, aes_key, 16);
    memcpy(kmesg.aid, AID, 8);
    //strncpy(kmesg.sn, (char*)&sn, sizeof(unsigned int));
    kmesg.sn = sn;;
    cmd.buff = &kmesg;

    ioctl(fd, IOCTL_DEV_LABEL, &cmd);

    printf("Terminal registers successfully\n");
    return 0;
}