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

#define MSG_LEN            125
#define MAX_PLOAD        125
#define NETLINK_PID     100

static char webserver[64];
static char registerserver[64];

// Netlink 消息格式
typedef  struct __channel_mes {
    unsigned char source[8];
    char states[8];
    unsigned char label[16];
    char notes[16];
    unsigned char aid[8];
    unsigned int delayTime;
} CHANNEL_MES;

typedef struct _user_msg_info
{
    struct nlmsghdr hdr;
    CHANNEL_MES mes;
} USER_MSG_INFO;

// 处理程序参数
int option_proc(int argc, char* argv[]);

// 将数据通过api发送到服务器后端
int send_to_server(CHANNEL_MES* mes);

// 向注册服务器询问aid是否存在
int exist_aid(char* aid);

// 用于保存返回内容的字符串
static char curl_res[1024];
// 回调函数，用于接收注册服务器的json数据
size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp);

int main(int argc, char *argv[])
{
    int ret;
    USER_MSG_INFO u_info;
    socklen_t len;
    int skfd;
    struct nlmsghdr *nlh = NULL;
    struct sockaddr_nl saddr, daddr; //saddr 表示源端口地址，daddr表示目的端口地址
    char *umsg = "user app starts";

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
            if(send_to_server(&u_info.mes) == -1)
                break;
        }
    }

    close(skfd);
    if(nlh != NULL) free((void*)nlh);
    return 0;
}

int option_proc(int argc, char* argv[]) {
    int opt = 0;
    int longindex = 0;
    const char getopt_str[] = "s:r:";
    static struct option long_options[] = {
        {"webserver", required_argument, 0, 's'},
        {"registerserver", required_argument, 0, 'r'}
    };

    while((opt = getopt_long(argc, argv, getopt_str, long_options, &longindex)) != -1) {
        switch(opt) {
            case 's':
                strncpy(webserver, optarg, 64);
                break;
            case 'r':
                strncpy(registerserver, optarg, 64);
                break;
            default:
                printf("未知的参数：%s\n", long_options[longindex].name);
                return -1;
        }
    }
    if(strlen(webserver) && strlen(registerserver))
        return 0;
    else {
        printf("所需参数:\n");
        printf("\t--webserver, -s\t\t\033[4mIP\033[0m\n");
        printf("\t\t指定数据展示的前端服务器地址\n");
        printf("\n");
        printf("\t--registerserver, -r\t\033[4mIP\033[0m\n");
        printf("\t\t指定注册与查询aid的服务器地址\n");
        return -1;
    }
}

int send_to_server(CHANNEL_MES* mes) {
    CURL *curl;
    CURLcode res;

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
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            printf("Connection to webserver %s failed\n", webserver);
            return -1;
        }
        curl_easy_cleanup(curl);
        return 0;
    }
    else
        return -1;
}

size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    // 这里可以做越界检查，确保数据不会超出data的容量
    memcpy(curl_res, contents, realsize);
    curl_res[realsize] = '\0';
    return realsize;
}

int exist_aid(char* aid) {
    CURL *curl;
    CURLcode res;

    // 解析JSON字符串
    struct json_object *parsed_json = NULL;
    struct json_object *json_exist;

    // 请求api地址
    char request_get[64] = "http://";
    strcat(request_get, registerserver);
    strcat(request_get, "/verify?aid=");
    strcat(request_get, aid);

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
            return -1;
        } else {
            parsed_json = json_tokener_parse(curl_res);
            if (!json_object_object_get_ex(parsed_json, "exist", &json_exist) || strcmp(json_object_get_string(json_exist), "true") != 0) {
                curl_easy_cleanup(curl);
                json_object_put(parsed_json);   // 释放JSON对象
                return 0;
            }
            else {
                curl_easy_cleanup(curl);
                json_object_put(parsed_json);   // 释放JSON对象
                return 1;
            }
        }
    }
}