#ifndef __IOCTL_CMD__
#define __IOCTL_CMD__

#define IOCTL_DEV_LABEL _IO(0X00, 0)
#define CMD_MAJOR 168
#define CMD_DEV_NAME "labelCmd"
#define CMD_DEV_PATH "/dev/labelCmd"

enum  CMD_TYPE {
    IOCTL_SET_AES_KEY = 1,      // IOCTL_SET_AES_KEY 表示负载是不属于本机的终端信息，内核需要存储在哈希表中
    IOCTL_SET_AID
};

typedef struct __set_key_mes {
    char mac[6];
    char aes_key[16];   // 这个 aes_key 是指与本机通信的时候使用的加密密钥
} SET_KEY_MES;

typedef struct __set_aid_mes {
    char aid[8];
    char ip6[16];   // 这个 aes_key 是指与本机通信的时候使用的加密密钥
    unsigned int sn;
} SET_AID_MES;

// 用户空间和内核模块交互的信息格式
typedef struct __ioctl_cmd {
    unsigned int type;
    void* buff;
} IOCTL_CMD;
#endif