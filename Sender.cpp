#pragma GCC diagnostic error "-std=c++11"

#include "cryptlib.h"
#include "secblock.h"
#include "eccrypto.h"
#include "osrng.h"
#include "nbtheory.h"
#include "sha3.h"
#include "algebra.h"
#include "hex.h"
#include<time.h>
#include<iostream>
#include <vector>
#include <iomanip>
#include "integer.h"
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <cstdlib>
#include <arpa/inet.h>
#include <unistd.h>
#include <random>
#include <fcntl.h>
#include "include/ioctl_cmd.h"

#define SERVER_IP "10.0.0.1"
#define SERVER_PORT 12345

struct CHPublicKey {
    CryptoPP::Integer p;
    CryptoPP::Integer q;
    CryptoPP::Integer g;
    CryptoPP::Integer y;
};

struct CHSecretKey {
    CryptoPP::Integer sk;
};

//生成公私钥，delta为安全参数，n_bits是为生成的大素数位数
std::pair<CHPublicKey, CHSecretKey> Keygen(int delta, int n_bits) {
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::Integer p, q;
    CryptoPP::PrimeAndGenerator pg(delta, prng, n_bits);

    p = pg.Prime();
    // q = (p - 1) / 2
    q = pg.SubPrime();

    // g [0, p]  BigInteger
    // g = g ^ 2 % p
    CryptoPP::Integer Two(2);
//    CryptoPP::Integer g(prng, 0, p);
    CryptoPP::Integer g(prng, n_bits);  
    g = a_exp_b_mod_c(g, Two, p);

    // sk [0, q] BigInteger
//    CryptoPP::Integer sk(prng, 0, q);
    CryptoPP::Integer sk(prng, n_bits);

    // y = g ^ sk % p
    CryptoPP::Integer y = a_exp_b_mod_c(g, sk, p);

    CHPublicKey PK{ p, q, g, y };
    CHSecretKey SK{ sk };

    return std::make_pair(PK, SK);
}

void sendString(int socket, const std::string& str) {
    // 发送字符串的长度
    int length = str.length();
    send(socket, &length, sizeof(length), 0);

    // 发送字符串的内容
    send(socket, str.c_str(), length, 0);
}

////获取本机mac地址
//bool getMacAddress(char mac[6]) {
//    struct ifreq ifr;
//    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
//
//    if (sockfd < 0) {
//        std::cerr << "Failed to create socket" << std::endl;
//        return false;
//    }
//
//    // 获取接口名称
//    strncpy(ifr.ifr_name, "ens33", IFNAMSIZ);
//
//    // 获取接口的MAC地址
//    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
//        std::cerr << "Failed to get MAC address" << std::endl;
//        close(sockfd);
//        return false;
//    }
//
//    // 将MAC地址复制到数组
//    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
//
//    close(sockfd);
//    return true;
//}

// 获取本机网络接口的MAC地址
// 获取本机网络接口的MAC地址
bool getMacAddress(const char* ifname, char macAddress[6]) {
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        return false;
    }

    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
        close(sockfd);
        return false;
    }

    close(sockfd);

    unsigned char* mac = reinterpret_cast<unsigned char*>(ifr.ifr_hwaddr.sa_data);
    std::memcpy(macAddress, mac, 6);

    return true;
}


// 发送MAC地址
void sendMacAddress(int sockfd, const char mac[6]) {
    // 发送MAC地址内容
    send(sockfd, mac, 6, 0);
}

// 生成随机的unsigned int值
unsigned int generateRandomValue() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned int> dis(0, std::numeric_limits<unsigned int>::max());
    return dis(gen);
}

// 发送unsigned int值
void sendUnsignedInt(int sockfd, unsigned int value) {
    // 转换为网络字节顺序
    unsigned int networkValue = htonl(value);

    // 发送值
    send(sockfd, &networkValue, sizeof(networkValue), 0);
}


std::string receiveString(int socket) {
    // 接收字符串的长度
    int length;
    recv(socket, &length, sizeof(length), 0);

    // 接收字符串的内容
    char buffer[length];
    recv(socket, buffer, length, 0);

    // 将接收到的内容转换为字符串类型
    std::string stringValue(buffer, length);

    return stringValue;
}

// 将 CryptoPP::Integer 转换为十六进制字符串
std::string IntegerToHexString(CryptoPP::Integer value) {

//    std::string hexString;
//    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hexString));
//    intValue.DEREncode(encoder);
//
//    return hexString;
    // 获取字节表示
    CryptoPP::SecByteBlock byteBlock(value.MinEncodedSize());
    value.Encode(byteBlock.BytePtr(), byteBlock.SizeInBytes());

    // 转换为十六进制字符串
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < byteBlock.SizeInBytes(); ++i) {
        oss << std::setw(2) << static_cast<unsigned int>(byteBlock[i]);
    }

    // 获取十六进制字符串
    std::string hexString = oss.str();

    return hexString;
}


// 将 CryptoPP::Integer 转换为字符串，确保长度为 128 位
std::string integerToPaddedString(const CryptoPP::Integer& value) {
    // 获取字节表示
    CryptoPP::SecByteBlock byteBlock(value.MinEncodedSize());
    value.Encode(byteBlock.BytePtr(), byteBlock.SizeInBytes());

    // 转换为十六进制字符串
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < byteBlock.SizeInBytes(); ++i) {
        oss << std::setw(2) << static_cast<unsigned int>(byteBlock[i]);
    }

    // 获取十六进制字符串
    std::string hexString = oss.str();

    // 如果长度不足 128 位，则在后面填充零
    size_t currentLength = hexString.length();
    if (currentLength < 32) {
        hexString = hexString + std::string(32 - currentLength, '0') ;
    }

    return hexString;
}

// 将十六进制字符串转换为 CryptoPP::Integer
CryptoPP::Integer stringToInteger(const std::string& hexString) {
    CryptoPP::Integer result;

    // 将十六进制字符串转换为字节表示
    CryptoPP::SecByteBlock byteBlock(hexString.size() / 2);
    CryptoPP::StringSource(hexString, true,
        new CryptoPP::HexDecoder(new CryptoPP::ArraySink(byteBlock, byteBlock.size())));

    // 从字节表示中构造整数
    result.Decode(byteBlock.BytePtr(), byteBlock.SizeInBytes());

    return result;
}


// CH=g^m*h^r mod p  生成变色龙哈希
CryptoPP::Integer chameleonHash(std::string msg, CHPublicKey pk, CryptoPP::Integer r) {

    CryptoPP::Integer m(msg.c_str());
    CryptoPP::Integer ch_digest;
//    clock_t start = clock();
    CryptoPP::Integer tmp_1 = a_exp_b_mod_c(pk.g, m, pk.p);
    CryptoPP::Integer tmp_2 = a_exp_b_mod_c(pk.y, r, pk.p);
    ch_digest = a_times_b_mod_c(tmp_1, tmp_2, pk.p);
//    clock_t finish = clock();
//    double compute_Times = (double)(finish - start) / CLOCKS_PER_SEC;
//    std::cout << "Compute time: " << compute_Times << "s." << std::endl;


    return ch_digest;
}

// CH=g^m*h^r =g^m'*h^r' mod p，可得m+rx=m'+r'x mod q，继而可计算出r'=(m-m'+rx)*x^(-1) mod q   生成新的随机数new_r使得哈希碰撞成功
CryptoPP::Integer forge(std::string ori_msg, std::string new_msg, CHPublicKey pk, CHSecretKey sk, CryptoPP::Integer r) {
    CryptoPP::Integer new_r;

    CryptoPP::Integer m(ori_msg.c_str());
    CryptoPP::Integer new_m(new_msg.c_str());


    CryptoPP::Integer diff = m - new_m;
    CryptoPP::Integer inverse = sk.sk.InverseMod(pk.q);
    CryptoPP::Integer tmp = diff * inverse;
    new_r = (tmp + r) % pk.q;

    return new_r;
}

//验证变色龙哈希是否相等，如果相等返回0
int chameleonHash_Ver(std::string msg, CHPublicKey pk, CryptoPP::Integer r, CryptoPP::Integer CHash) {
    CryptoPP::Integer ch = chameleonHash(msg, pk, r);
    std::cout << "Original_hash: " << CHash << std::endl;
    std::cout << "New_hash: " << ch << std::endl;
    if (ch == CHash)
        return 0;
    return 1;
}

void generateRandomAid(char* aid, int size) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(0, 255);

    for (int i = 0; i < size; ++i) {
        aid[i] = static_cast<char>(dis(gen));
    }
}

void stringToCharArray(const std::string& hexString, char* arr, int size) {
    int strLength = hexString.length();

    for (int i = 0; i < size; ++i) {
        std::istringstream iss(hexString.substr(2 * i, 2));
        int value;
        iss >> std::hex >> value;  // 将两个字符解析为一个十六进制数
        arr[i] = static_cast<char>(value);
    }
}


int main(int argc, const char* argv[]) {
    auto [pk, sk] = Keygen(1, 128);
    CryptoPP::AutoSeededRandomPool prng;
//    CryptoPP::Integer r(prng, 0, pk.q);
    CryptoPP::Integer r(prng, 128);

    std::string s = "2023110898abjghgjhbc";
//    std::string new_s = "2019212338hfgg";
    clock_t start = clock();
    CryptoPP::Integer ch = chameleonHash(s, pk, r);
    clock_t finish = clock();
//    size_t byteSize = ch.ByteCount();
//    std::vector<byte> byteBuffer(byteSize);
//    ch.Encode(byteBuffer.data(), byteSize);
    std::cout << "chameleon hash: " << ch << std::endl;
    std::cout << "Hexadecimal chameleon hash: " << IntegerToHexString(ch) << std::endl;
    double Times = (double)(finish - start) / CLOCKS_PER_SEC;
    std::cout << "Generation time: " << Times << "s." << std::endl;

    // 将 CryptoPP::Integer 转换为128位的16进制字符串
    std::string ch_String = integerToPaddedString(ch);
    std::cout << "ch_String: " << ch_String << std::endl;
    // 将字符串恢复为原来的CryptoPP::Integer类型
//    CryptoPP::Integer re = stringToInteger(ch_String);
//    std::cout << "Stringtohash: " << re << std::endl;

    std::cout << "准备接收新信息以生成新随机数" << std::endl;
	

    // 创建Socket
    int socketHandle1 = socket(AF_INET, SOCK_STREAM, 0);
    if (socketHandle1 == -1) {
        std::cerr << "Failed to create socket" << std::endl;
        return 1;
    }

    // 绑定Socket到端口
    sockaddr_in serverAddress1{};
    serverAddress1.sin_family = AF_INET;
    serverAddress1.sin_addr.s_addr = INADDR_ANY;
    serverAddress1.sin_port = htons(SERVER_PORT);
    if (bind(socketHandle1, (struct sockaddr*)&serverAddress1, sizeof(serverAddress1)) < 0) {
        std::cerr << "Failed to bind socket" << std::endl;
        return 1;
    }

    // 监听连接
    if (listen(socketHandle1, 1) < 0) {
        std::cerr << "Failed to listen for connections" << std::endl;
        return 1;
    }

    // 接受连接
    int clientSocket1 = accept(socketHandle1, nullptr, nullptr);
    if (clientSocket1 < 0) {
        std::cerr << "Failed to accept connection" << std::endl;
        return 1;
    }
    // 接收整数和字符串
    std::string new_s = receiveString(clientSocket1);
    // 关闭Socket连接
    close(clientSocket1);
    close(socketHandle1);

    std::cout << "接收新信息:"<< new_s  << std::endl;	
    CryptoPP::Integer new_r = forge(s, new_s, pk, sk, r);
    std::cout << "new_r: " << new_r << std::endl;
    // 创建Socket
    int socketHandle = socket(AF_INET, SOCK_STREAM, 0);
    if (socketHandle == -1) {
        std::cerr << "Failed to create socket" << std::endl;
        return 1;
    }

    // 设置服务器地址
    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &(serverAddress.sin_addr)) <= 0) {
        std::cerr << "Failed to set server address" << std::endl;
        return 1;
    }

    // 连接到服务器
    if (connect(socketHandle, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        std::cerr << "Failed to connect to server" << std::endl;
        return 1;
    }
    // 要发送的数据
    std::string r_String = IntegerToHexString(new_r);
    std::string p_String = IntegerToHexString(pk.p);
    std::string q_String = IntegerToHexString(pk.q);
    std::string g_String = IntegerToHexString(pk.g);
    std::string y_String = IntegerToHexString(pk.y);
    // 生成随机的unsigned int值
    unsigned int sn = generateRandomValue();
    std::cout << "sn: " << sn << std::endl;
    // 发送unsigned int值
    sendUnsignedInt(socketHandle, sn);
    // 发送整数和字符串
    sendString(socketHandle, p_String);
    sendString(socketHandle, q_String);
    sendString(socketHandle, g_String);
    sendString(socketHandle, y_String);
    sendString(socketHandle, new_s);
    sendString(socketHandle,r_String);
    // 获取本机MAC地址
    const char* interfaceName = "ens34";
    char macAddress[6];

    if (getMacAddress(interfaceName, macAddress)) {
        
    } else {
        std::cout << "Failed to get MAC address." << std::endl;
    }
    printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", macAddress[0]&0xff, macAddress[1]&0xff, macAddress[2]&0xff, macAddress[3]&0xff, macAddress[4]&0xff, macAddress[5]&0xff);
    // 发送MAC地址
    sendMacAddress(socketHandle, macAddress);
    // 关闭Socket连接
    close(socketHandle);
    char aid[8];
    generateRandomAid(aid, sizeof(aid));
    std::cout << "aid: " << aid << std::endl;

    char aes[16];
    stringToCharArray(ch_String, aes, sizeof(aes));
    SET_MYSELF_MES setMyselfMes;
    setMyselfMes.sn = sn;
    std::memcpy(setMyselfMes.aes_key, aes, sizeof(aes));
    std::memcpy(setMyselfMes.aid, aid, sizeof(aid));
    IOCTL_CMD ioctlCmd;
    ioctlCmd.type = IOCTL_SET_MYSELF;
    ioctlCmd.buff = &setMyselfMes;
    int fd;
    // 打开字符设备文件发送命令
    fd = open(CMD_DEV_PATH, O_RDONLY);
    if(fd <= 0) {
        printf("Open cmd device error\n");
        return -1;
    }
    ioctl(fd, IOCTL_DEV_LABEL, &ioctlCmd);

//    std::string new_s = "2019212338hfgg";
//    clock_t forge_start = clock();
//    CryptoPP::Integer new_r = forge(s, new_s, pk, sk, r);
//    clock_t forge_finish = clock();
//    std::cout << "r_1: " << r << std::endl;
//    std::cout << "r_2: " << new_r << std::endl;
//    double forge_Times = (double)(forge_finish - forge_start) / CLOCKS_PER_SEC;
//    std::cout << "Forge time: " << forge_Times << "s." << std::endl;
//
//    //    auto re1 = chameleonHash(s, pk, r);
//    //    auto re2 = chameleonHash(new_s, pk, new_r);
//    //    std::cout << "Original_hash: " << re1 << std::endl;
//    //    std::cout << "Now_hash: " << re2 << std::endl;
//
//    if (chameleonHash_Ver(new_s, pk, new_r, ch) == 0) {
//        std::cout << "The hash collision succeeded." << std::endl;
//    }

    return 0;
}
