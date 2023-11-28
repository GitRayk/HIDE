#ifndef __IOCTL_CMD__
#define __IOCTL_CMD__

#define IOCTL_DEV_LABEL _IO(0X00, 0)
#define CMD_MAJOR 168
#define CMD_DEV_NAME "labelCmd"
#define CMD_DEV_PATH "/dev/labelCmd"

enum  CMD_TYPE {
    IOCTL_SET_AID = 1,
    IOCTL_SET_SN,
    IOCTL_SET_AES_KEY
};

// 用户空间和内核模块交互的信息格式
typedef struct __ioctl_cmd {
    unsigned int type;
    void* buff;
} IOCTL_CMD;
#endif