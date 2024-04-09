#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <curl/curl.h>
#include <getopt.h>
#include <json-c/json.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <time.h>

#include "channel_mes.h"
#include "ioctl_cmd.h"
#include "pthread_pool.h"

#define MSG_LEN            125
#define MAX_PLOAD        125
#define NETLINK_PID     100

static char webserver[64];
static char registerserver[64];
static char dataserver[64];

typedef struct _user_msg_info
{
    struct nlmsghdr hdr;
    CHANNEL_MES mes;
} USER_MSG_INFO;

// Create a list to store the exsiting AIDs
#define MAX_AID_NUM 128
static unsigned char aid_list[MAX_AID_NUM][8];
static unsigned int aid_num = 0;
static unsigned int send_count = 0;
static unsigned int task_count = 0;
POOL pool;

pthread_mutex_t count_mutex = PTHREAD_MUTEX_INITIALIZER;

// 处理程序参数
int option_proc(int argc, char* argv[]);

// 将数据通过api发送到服务器后端
void send_to_server(void  *mes);

// 向注册服务器询问aid是否存在
int exist_aid(unsigned char* aid);

void request_get_map(unsigned int type, unsigned char *data);

// 用于保存返回内容的字符串
static char curl_res[1024];
// 回调函数，用于接收注册服务器的json数据
size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp);
// 回调函数，用于处理ipv6地址和aid的映射关系
size_t callback_get_map(void *contents, size_t size, size_t nmemb, void *userp);

// process the signal SIGINT
void exit_of_program(int signo) {
    printf("Task count: %d\n", task_count);
    printf("Send count: %d\n", send_count);
    printf("Remain task: %d\n", (pool.task_queue_tail + TASK_QUEUE_LEN - pool.task_queue_head) % TASK_QUEUE_LEN);
    exit(0);
}

int main(int argc, char *argv[])
{
    int ret;
    USER_MSG_INFO u_info;
    UPLOAD_MES *u_upload_data;
    socklen_t len;
    int skfd;
    struct nlmsghdr *nlh = NULL;
    struct sockaddr_nl saddr, daddr; //saddr 表示源端口地址，daddr表示目的端口地址
    char *umsg = "user app starts";
    // POOL pool;

    // 初始化线程池
    init_pool(&pool);

    // set signal handler for SIGINT
    signal(SIGINT, exit_of_program);

    if(option_proc(argc, argv) != 0) {
        return -1;
    }

    /* 创建NETLINK socket */ 
    skfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USERSOCK);
    if(skfd == -1)
    {
        perror("create socket error\n");
        return -1;
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.nl_family = AF_NETLINK; //AF_NETLINK
    saddr.nl_pid = NETLINK_PID;  //端口号(port ID) 
    saddr.nl_groups = 0;
    if(bind(skfd, (struct sockaddr *)&saddr, sizeof(saddr)) != 0)
    {
        perror("bind() error\n");
        close(skfd);
        return -1;
    }

    memset(&daddr, 0, sizeof(daddr));
    daddr.nl_family = AF_NETLINK;
    daddr.nl_pid = 0; // to kernel 
    daddr.nl_groups = 0;

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PLOAD));
    memset(nlh, 0, sizeof(struct nlmsghdr));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PLOAD);
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_type = 0;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_pid = saddr.nl_pid; //self port

    // 向内核发送一个 hello 消息，告知当前应用程序的pid
    memcpy(NLMSG_DATA(nlh), umsg, strlen(umsg)); // 拷贝发送的数据到报文头指向内存后面
    ret = sendto(skfd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr_nl));
    if(!ret)
    {
        perror("sendto error\n");
        close(skfd);
        exit(-1);
    }
    
    // 循环监听内核通过 netlink 发送的消息
    while(1) {
        memset(&u_info, 0, sizeof(u_info));
        len = sizeof(struct sockaddr_nl);
        ret = recvfrom(skfd, &u_info, sizeof(USER_MSG_INFO), 0, (struct sockaddr *)&daddr, &len);
        if(!ret)
        {
            perror("recv form kernel error\n");
            close(skfd);
            exit(-1);
        }
        else {
            // 将内核发送来的数据包信息进行处理，然后交付给前端服务器的数据库
            if(u_info.mes.type == NL_UPLOAD_LOG) {
                // send_to_server(&u_info.mes.upload_data);
                // 为每个任务从堆中分配空间以持久地保存参数，并在任务函数内释放该空间
                u_upload_data = (UPLOAD_MES*)malloc(sizeof(UPLOAD_MES));
                memcpy(u_upload_data, &u_info.mes.upload_data, sizeof(UPLOAD_MES));
                execute_task(&pool, send_to_server, u_upload_data);
                task_count++;
            }
            else if(u_info.mes.type == NL_REQUEST_AID || u_info.mes.type == NL_REQUEST_IP6) {
                request_get_map(u_info.mes.type, (unsigned char*)((&u_info.mes.type)+1));
            }
            else {
                printf("Receive unrecognized channel message type: %d\n", u_info.mes.type);
            }
        }
    }

    close(skfd);
    if(nlh != NULL) free((void*)nlh);
    return 0;
}

int option_proc(int argc, char* argv[]) {
    int opt = 0;
    int longindex = 0;
    const char getopt_str[] = "s:r:d:";
    static struct option long_options[] = {
        {"webserver", required_argument, 0, 's'},
        {"registerserver", required_argument, 0, 'r'},
        {"dataserver", required_argument, 0, 'd'}
    };

    while((opt = getopt_long(argc, argv, getopt_str, long_options, &longindex)) != -1) {
        switch(opt) {
            case 's':
                strncpy(webserver, optarg, 64);
                break;
            case 'r':
                strncpy(registerserver, optarg, 64);
                break;
            case 'd':
                strncpy(dataserver, optarg, 64);
                break;
            default:
                printf("未知的参数：%s\n", long_options[longindex].name);
                return -1;
        }
    }
    if(strlen(webserver) && strlen(registerserver) && strlen(dataserver))
        return 0;
    else {
        printf("所需参数:\n");
        printf("\t--webserver, -s\t\t\033[4mIP\033[0m\n");
        printf("\t\t指定数据展示的前端服务器地址\n");
        printf("\n");
        printf("\t--registerserver, -r\t\033[4mIP\033[0m\n");
        printf("\t\t指定注册与查询aid的服务器地址\n");
        printf("\n");
        printf("\t--dataserver, -d\t\033[4mIP\033[0m\n");
        printf("\t\t指定存储和查询aid-ipv6的数据服务器\n");
        return -1;
    }
}

size_t upload_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    return realsize;
}

void send_to_server(void  *arg) {
    CURL *curl;
    CURLcode res;

    if(arg == NULL)
        return;

    UPLOAD_MES *mes = (UPLOAD_MES*)arg;

    if(strcmp(mes->states, "good") == 0 &&  1 != exist_aid(mes->aid)) {
        strncpy(mes->states, "bad", 8);
        strncpy(mes->notes, "AID DOES NOT EXIST", 24);
    }
    // 请求api地址
    char request_post[64] = "http://";
    strcat(request_post, webserver);
    strcat(request_post, "/api/upload.php");

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(curl, CURLOPT_URL, request_post);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "User-Agent: Apifox/1.0.0 (https://apifox.com)");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, upload_callback);     // 如果不设置回调函数，则会在获取到响应之后会输出响应内容，因此这里随意设置一个回调函数
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
        
        // 将消息体构造成json格式的字符串
        char source[24];
       sprintf(source, "%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X", mes->source[0], mes->source[1], mes->source[2], mes->source[3],
            mes->source[4], mes->source[5], mes->source[6], mes->source[7]);
        char aid[24];
       sprintf(aid, "%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X", mes->aid[0], mes->aid[1], mes->aid[2], mes->aid[3],
            mes->aid[4], mes->aid[5], mes->aid[6], mes->aid[7]);
        char label[40];
        sprintf(label, "%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X", mes->label[0], mes->label[1], mes->label[2], mes->label[3],
            mes->label[4], mes->label[5], mes->label[6], mes->label[7],
            mes->label[8], mes->label[9], mes->label[10], mes->label[11],
            mes->label[12], mes->label[13], mes->label[14], mes->label[15]);
        
       char data[256];
       memset(data, '\0', 256);
       sprintf(data, "{\n"
            "\t\"source\": \"%s\",\n"
            "\t\"states\": \"%s\",\n"
            "\t\"aid\": \"%s\",\n"
            "\t\"label\": \"%s\",\n"
            "\t\"delayTime\": %d ,\n"
            "\t\"notes\": \"%s\"\n}", source, mes->states, aid, label, mes->delayTime, mes->notes);

        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        curl_easy_perform(curl);

        pthread_mutex_lock(&count_mutex);
        send_count++;
        pthread_mutex_unlock(&count_mutex);

        curl_easy_cleanup(curl);
        free(mes);
    }
}

size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    // 这里可以做越界检查，确保数据不会超出data的容量
    memcpy(curl_res, contents, realsize);
    curl_res[realsize] = '\0';
    return realsize;
}

int exist_aid(unsigned char* aid) {
    CURL *curl;
    CURLcode res;

    // 解析JSON字符串
    struct json_object *parsed_json = NULL;
    struct json_object *json_exist;

    // 请求api地址
    char request_get[128] = "http://";
    sprintf(request_get, "http://%s:8088/verify?aid=%02x%02x%02x%02x%02x%02x%02x%02x", registerserver, aid[0], aid[1], aid[2], aid[3], aid[4], aid[5], aid[6], aid[7]);

    // 先从当前缓存的aid列表中确认aid是否存在
    for(int i = 0; i < aid_num; i++) {// 遍历aid列表
        if(memcmp(aid_list[i], aid, 8) == 0) {
            return 1;
        }
    }

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
        curl_easy_setopt(curl, CURLOPT_URL, request_get);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "User-Agent: Apifox/1.0.0 (https://apifox.com)");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        res = curl_easy_perform(curl);  

        if(res != CURLE_OK) {
            printf("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            return -1;
        } else {
            parsed_json = json_tokener_parse(curl_res);
            if (!json_object_object_get_ex(parsed_json, "exists", &json_exist) || strcmp(json_object_get_string(json_exist), "true") != 0) {
                curl_easy_cleanup(curl);
                json_object_put(parsed_json);   // 释放JSON对象
                                return 0;
            }
            else {
                curl_easy_cleanup(curl);
                json_object_put(parsed_json);   // 释放JSON对象
                
                // 将aid加入到缓存列表中
                if(aid_num < MAX_AID_NUM) {
                    memcpy(aid_list[aid_num], aid, 8);
                    aid_num++;
                }
                else {
                    // 当aid缓存列表满时，可以设置某种策略进行数据替换，如 LRU 或 LFU 算法
                    printf("AID cache is full\n");
                }
                return 1;
            }
        }
    }
}

size_t callback_get_map(void *contents, size_t size, size_t nmemb, void *userp) {
    int fd;
    IOCTL_CMD cmd;
    SET_AID_MES kern_mes;
    int i;
    // 解析JSON字符串
    struct json_object *parsed_json = NULL;
    struct json_object *json_result;
    struct json_object *json_ip6, *json_aid, *json_sn;

    unsigned char data[1024];
    size_t realsize = size * nmemb;
    // 这里可以做越界检查，确保数据不会超出data的容量
    memcpy(data, contents, realsize);
    data[realsize] = '\0';

    parsed_json = json_tokener_parse(data);
    if (!json_object_object_get_ex(parsed_json, "result", &json_result) || strcmp(json_object_get_string(json_result), "success") != 0) {
        if(strcmp(json_object_get_string(json_result), "null"))     printf("%s\n", json_object_get_string(json_result));
        json_object_put(parsed_json);   // 释放JSON对象
        return 0;
    }
    else {
        // 将获取到的aid-ipv6映射下发给内核
        json_object_object_get_ex(parsed_json, "ip6", &json_ip6);
        json_object_object_get_ex(parsed_json, "aid", &json_aid);
        json_object_object_get_ex(parsed_json, "sn", &json_sn);
        // 要将获取的字符串转换成十六进制的字节表示
        for(i = 0; i < 16; i += 2) sscanf(json_object_get_string(json_aid) + i, "%2hhx", &kern_mes.aid[i/2]);
        for(i = 0; i < 32; i += 2) sscanf(json_object_get_string(json_ip6) + i, "%2hhx", &kern_mes.ip6[i/2]);
        kern_mes.sn = json_object_get_int(json_sn);
        // 打开字符设备文件发送命令
        fd = open(CMD_DEV_PATH, O_RDONLY);
        if(fd <= 0) {
            printf("Open cmd device error\n");
            return -1;
        }
        cmd.type = IOCTL_SET_AID;
        cmd.buff = &kern_mes;
        ioctl(fd, IOCTL_DEV_LABEL, &cmd);

        close(fd);
        json_object_put(parsed_json);   // 释放JSON对象
        return 1;
    }
}

void request_get_map(unsigned int type, unsigned char *data) {
    CURL *curl;
    // 请求api地址
    char request_get[64] = "http://";
    strcat(request_get, dataserver);
    strcat(request_get, "/api/getAidMap.php");

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(curl, CURLOPT_URL, request_get);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback_get_map);
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "User-Agent: Apifox/1.0.0 (https://apifox.com)");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        char mesg[256];
       memset(mesg, '\0', 256);
       if(type == NL_REQUEST_AID) {
            sprintf(mesg, "{\n"
            "\t\"ip6\": \"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\"\n}", 
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]);
       }
       else {
            sprintf(mesg, "{\n"
            "\t\"aid\":\"%02x%02x%02x%02x%02x%02x%02x%02x\"\n}",
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);
       }
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, mesg);
        curl_easy_perform(curl);
    }
    curl_easy_cleanup(curl);
}