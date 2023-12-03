#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include "ioctl_cmd.h"

int main(int argc, char **argv) {
    unsigned int sn = 12;
    char aes_key[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
    };
    char mac[6] = {
        0x00, 0x0c, 0x29, 0x83, 0x1a, 0x20
    };
    int fd;
    IOCTL_CMD   cmd;
    SET_KEY_MES kmesg;

    // 打开字符设备文件发送命令
    fd = open(CMD_DEV_PATH, O_RDONLY);
    if(fd <= 0) {
        printf("Open cmd device %s error: %s\n", CMD_DEV_PATH, strerror(errno));
        return -1;
    }
    
    cmd.type = IOCTL_SET_AES_KEY;
    memcpy(kmesg.aes_key, aes_key, 16);
    printf("app: Insert data: %02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    memcpy(kmesg.mac, mac, 6);
    printf("app: Insert data: %02X:%02X:%02X:%02X:%02X:%02X\n", kmesg.mac[0], kmesg.mac[1], kmesg.mac[2], kmesg.mac[3], kmesg.mac[4], kmesg.mac[5]);
    // strncpy(kmesg.sn, (char*)&sn, sizeof(unsigned int));
    kmesg.sn = sn;
    cmd.buff = &kmesg;

    ioctl(fd, IOCTL_DEV_LABEL, &cmd);

    printf("Terminal registers successfully\n");
    return 0;
}