#ifndef __CHANNEL_MES__
#define __CHANNEL_MES__
// 定义 netlink 传递的消息类型
enum CHANNEL_TYPE {
    NL_UPLOAD_LOG = 1, // 通知应用程序向前端服务器提交记录信息
    NL_REQUEST_AID,        // 通知应用程序向数据服务器查询aid和ip地址的映射关系
    NL_REQUEST_IP6
};

typedef  struct __channel_upload_mes {
    unsigned char source[8];
    char states[8];
    unsigned char label[16];
    char notes[24];
    unsigned char aid[8];
    unsigned int delayTime;
} UPLOAD_MES;


typedef struct __channel_mes {
    unsigned int type;
    union {
        UPLOAD_MES upload_data;
        unsigned char ip6[16];
        unsigned char aid[8];
    };
} CHANNEL_MES;
#endif