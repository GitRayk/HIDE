#include <stdio.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <time.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>

#include "ioctl_cmd.h"

#define LOCAL_LINK "\xfe\x80\x00\x00\x00"
#define LOOPBACK_LINK "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"

#define DEBUG_ENABLE 1
#if DEBUG_ENABLE
#define DEBUG_PRINT(fmt, args...) printf(fmt, ##args)
#else
#define DEBUG_PRINT(fmt, args...)
#endif

static char registerserver[64];
static char dataserver[64];
// 用于保存返回内容的字符串
static char curl_res[1024];

// 处理程序参数
int option_proc(int argc, char* argv[]);
// 向注册服务器发送注册请求，获取aid(和did)
int register_terminal(char *aid);
// 回调函数，用于接收注册服务器的json数据
size_t register_callback(void *contents, size_t size, size_t nmemb, void *userp);
// 将aid-ipv6-sn下发给内核
void distribute_to_kern(unsigned char *ipv6_address, unsigned char *aid, unsigned int sn);
void request_set_map(unsigned char *ipv6_address, unsigned char *aid, unsigned int sn);


int main(int argc, char *argv[]) {
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *addr = NULL;
    struct sockaddr_in6 *ipv6;
    unsigned char *ipv6_address = NULL;
    char aid[8];
    unsigned int sn;

    if(option_proc(argc, argv) != 0) {
        return -1;
    }

    // 获取本地网络接口信息
    if (getifaddrs(&interfaces) == 0) {
        for (addr = interfaces; addr != NULL; addr = addr->ifa_next) {
            if (addr->ifa_addr && addr->ifa_addr->sa_family == AF_INET6) {
                ipv6 = (struct sockaddr_in6 *)addr->ifa_addr;
                ipv6_address = (unsigned char*)&ipv6->sin6_addr;

                // 首先排除掉所有的本地链路地址和环回地址，这些地址不会出现在网络上，所以无需注册
                if(!memcmp(ipv6_address, LOCAL_LINK, 5) || !memcmp(ipv6_address, LOOPBACK_LINK, 16))  continue;   
                
                // 注册，然后生成一个随机数sn，之后将所有数据下发给内核
                DEBUG_PRINT("注册信息：\nipv6_address: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", ipv6_address[0], ipv6_address[1], ipv6_address[2], ipv6_address[3], ipv6_address[4], ipv6_address[5], ipv6_address[6], ipv6_address[7], ipv6_address[8], ipv6_address[9], ipv6_address[10], ipv6_address[11], ipv6_address[12], ipv6_address[13], ipv6_address[14], ipv6_address[15]);
                if(register_terminal(aid) == 0) {
                    srand((unsigned int)time(NULL));
                    sn = rand();
                    distribute_to_kern(ipv6_address, aid, sn);
                    request_set_map(ipv6_address, aid, sn);
                    printf("注册成功\n");
                }
                else printf("注册失败\n");
            }
        }
        freeifaddrs(interfaces);
    }
}


int option_proc(int argc, char* argv[]) {
    int opt = 0;
    int longindex = 0;
    const char getopt_str[] = "r:d:";
    static struct option long_options[] = {
        {"registerserver", required_argument, 0, 'r'},
        {"dataserver", required_argument, 0, 'd'}
    };

    while((opt = getopt_long(argc, argv, getopt_str, long_options, &longindex)) != -1) {
        switch(opt) {
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
    if(strlen(registerserver) && strlen(dataserver))
        return 0;
    else {
        printf("所需参数:\n");
        printf("\t--registerserver, -r\t\033[4mIP\033[0m\n");
        printf("\t\t指定注册与查询aid的服务器地址\n");
        printf("\n");
        printf("\t--dataserver, -d\t\033[4mIP\033[0m\n");
        printf("\t\t指定存储和查询aid-ipv6的数据服务器\n");
        return -1;
    }
}


int register_terminal(char *aid) {
    CURL *curl;
    CURLcode res;

    // 解析JSON字符串
    struct json_object *parsed_json = NULL;
    struct json_object *json_status;
    struct json_object *json_aid;
    struct json_object *json_did;
    struct json_object *json_publickey;
    int i;

    // 请求api地址
    char request_get[64] = "http://";
    strcat(request_get, registerserver);
    strcat(request_get, ":8088/generate");

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
        curl_easy_setopt(curl, CURLOPT_URL, request_get);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, register_callback);
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "User-Agent: Apifox/1.0.0 (https://apifox.com)");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        res = curl_easy_perform(curl);

         if(res != CURLE_OK) {
            return -1;
        } else {
            parsed_json = json_tokener_parse(curl_res);
            if (!json_object_object_get_ex(parsed_json, "status", &json_status) || strcmp(json_object_get_string(json_status), "success") != 0) {
                curl_easy_cleanup(curl);
                json_object_put(parsed_json);   // 释放JSON对象
                return -1;
            }
            else {
                json_object_object_get_ex(parsed_json, "aid", &json_aid);
                json_object_object_get_ex(parsed_json, "did", &json_did);
                json_object_object_get_ex(parsed_json, "publickey", &json_publickey);

                DEBUG_PRINT("aid: %s\n", json_object_get_string(json_aid));
                DEBUG_PRINT("did: %s\n", json_object_get_string(json_did));
                DEBUG_PRINT("publickey: %s\n", json_object_get_string(json_publickey));

                for(i = 0; i < 16; i += 2)  sscanf(json_object_get_string(json_aid) + i, "%2hhx", &aid[i/2]);
                curl_easy_cleanup(curl);
                json_object_put(parsed_json);   // 释放JSON对象
                return 0;
            }
        }
    }
}

size_t register_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    // 这里可以做越界检查，确保数据不会超出data的容量
    memcpy(curl_res, contents, realsize);
    curl_res[realsize] = '\0';
    return realsize;
}

void distribute_to_kern(unsigned char *ipv6_address, unsigned char *aid, unsigned int sn) {
    int fd;
    IOCTL_CMD cmd;
    SET_AID_MES kern_mes;

    memcpy(kern_mes.ip6, ipv6_address, 16);
    memcpy(kern_mes.aid, aid, 8);
    kern_mes.sn = sn;

    // 打开字符设备文件发送命令
    fd = open(CMD_DEV_PATH, O_RDONLY);
    if(fd <= 0) {
    printf("Open cmd device error\n");
        return ;
    }
    cmd.type = IOCTL_SET_AID;
    cmd.buff = &kern_mes;
    ioctl(fd, IOCTL_DEV_LABEL, &cmd);

    close(fd);
}

void request_set_map(unsigned char *ipv6_address, unsigned char *aid, unsigned int sn) {
    CURL *curl;
    CURLcode res;

    // 请求api地址
    char request_get[64] = "http://";
    strcat(request_get, dataserver);
    strcat(request_get, "/api/setAidMap.php");

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(curl, CURLOPT_URL, request_get);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "User-Agent: Apifox/1.0.0 (https://apifox.com)");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        char mesg[256];
        memset(mesg, '\0', 256);
        sprintf(mesg, "{\n"
            "\t\"aid\":\"%02x%02x%02x%02x%02x%02x%02x%02x\",\n"
            "\t\"ip6\":\"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\",\n"
            "\t\"sn\": %d\n}",
            aid[0], aid[1], aid[2], aid[3], aid[4], aid[5], aid[6], aid[7],
            ipv6_address[0], ipv6_address[1], ipv6_address[2], ipv6_address[3], ipv6_address[4], ipv6_address[5], ipv6_address[6], ipv6_address[7], ipv6_address[8], ipv6_address[9], ipv6_address[10], ipv6_address[11], ipv6_address[12], ipv6_address[13], ipv6_address[14], ipv6_address[15],
            sn);

        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, mesg);
        res = curl_easy_perform(curl);
    }
    curl_easy_cleanup(curl);
}