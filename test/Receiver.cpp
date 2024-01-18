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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <cstdlib>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "include/ioctl_cmd.h"

#define SERVER_IP "10.0.0.2"
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

// 接收MAC地址
void receiveMacAddress(int sockfd, char mac[6]) {
    // 接收MAC地址内容
    recv(sockfd, mac, 6, 0);
}

// 接收unsigned int值
unsigned int receiveUnsignedInt(int sockfd) {
    unsigned int value;

    // 接收值
    recv(sockfd, &value, sizeof(value), 0);

    // 转换为主机字节顺序
    return ntohl(value);
}

// 将 CryptoPP::Integer 转换为十六进制字符串
std::string IntegerToHexString(CryptoPP::Integer intValue) {

    std::string hexString;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hexString));
    intValue.DEREncode(encoder);

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
    std::string new_s = "2019212338hfgg";
    char mac[6];
    // 创建Socket
    int socketHandle1 = socket(AF_INET, SOCK_STREAM, 0);
    if (socketHandle1 == -1) {
        std::cerr << "Failed to create socket" << std::endl;
        return 1;
    }

    // 设置服务器地址
    sockaddr_in serverAddress1{};
    serverAddress1.sin_family = AF_INET;
    serverAddress1.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &(serverAddress1.sin_addr)) <= 0) {
        std::cerr << "Failed to set server address" << std::endl;
        return 1;
    }

    // 连接到服务器
    if (connect(socketHandle1, (struct sockaddr*)&serverAddress1, sizeof(serverAddress1)) < 0) {
        std::cerr << "Failed to connect to server" << std::endl;
        return 1;
    }
    // 发送整数和字符串
    sendString(socketHandle1, new_s);
    // 关闭Socket连接
    close(socketHandle1);




    std::cout << "准备接收随机数及公钥生成哈希" << std::endl;
    // 创建Socket
    int socketHandle = socket(AF_INET, SOCK_STREAM, 0);
    if (socketHandle == -1) {
        std::cerr << "Failed to create socket" << std::endl;
        return 1;
    }

    // 绑定Socket到端口
    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(SERVER_PORT);
    if (bind(socketHandle, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        std::cerr << "Failed to bind socket" << std::endl;
        return 1;
    }

    // 监听连接
    if (listen(socketHandle, 1) < 0) {
        std::cerr << "Failed to listen for connections" << std::endl;
        return 1;
    }

    // 接受连接
    int clientSocket = accept(socketHandle, nullptr, nullptr);
    if (clientSocket < 0) {
        std::cerr << "Failed to accept connection" << std::endl;
        return 1;
    }

    // 接收整数和字符串
    unsigned int sn = receiveUnsignedInt(clientSocket);
    std::string p = receiveString(clientSocket);
    std::string q = receiveString(clientSocket);
    std::string g = receiveString(clientSocket);
    std::string y = receiveString(clientSocket);
    std::string s = receiveString(clientSocket);
    std::string r_String = receiveString(clientSocket);
    receiveMacAddress(clientSocket, mac);
    // 打印接收到的数据

    // 关闭Socket连接
    close(clientSocket);
    close(socketHandle);
    CHPublicKey pk;
    pk.p = stringToInteger(p);
    pk.q = stringToInteger(q);
    pk.g = stringToInteger(g);
    pk.y = stringToInteger(y);
    CryptoPP::Integer r = stringToInteger(r_String);
    std::cout << "r: " << r << std::endl;
    std::cout << "sn: " << sn << std::endl;
    CryptoPP::Integer ch = chameleonHash(s, pk, r);
    std::cout << "chameleon hash: " << ch << std::endl;
    // 打印接收到的MAC地址
    printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0]&0xff, mac[1]&0xff, mac[2]&0xff, mac[3]&0xff, mac[4]&0xff, mac[5]&0xff);
    std::string ch_String = integerToPaddedString(ch);
    char aes[16];
    stringToCharArray(ch_String, aes, sizeof(aes));
    printf("aes_key: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n", aes[0]&0xff, aes[1]&0xff, aes[2]&0xff, aes[3]&0xff, aes[4]&0xff, aes[5]&0xff, aes[6]&0xff, aes[7]&0xff, aes[8]&0xff, aes[9]&0xff, aes[10]&0xff, aes[11]&0xff, aes[12]&0xff, aes[13]&0xff, aes[14]&0xff, aes[15]&0xff);
    SET_KEY_MES setKeyMes;
    std::memcpy(setKeyMes.mac, mac, sizeof(mac));
    std::memcpy(setKeyMes.aes_key, aes, sizeof(aes));
    setKeyMes.sn = sn;
    printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", setKeyMes.mac[0]&0xff, setKeyMes.mac[1]&0xff, setKeyMes.mac[2]&0xff, setKeyMes.mac[3]&0xff, setKeyMes.mac[4]&0xff, setKeyMes.mac[5]&0xff);
    IOCTL_CMD ioctlCmd;
    ioctlCmd.type = IOCTL_SET_AES_KEY;
    ioctlCmd.buff = &setKeyMes;
    int fd;
    // 打开字符设备文件发送命令
    fd = open(CMD_DEV_PATH, O_RDONLY);
    if(fd <= 0) {
        printf("Open cmd device error\n");
        return -1;
    }
    ioctl(fd, IOCTL_DEV_LABEL, &ioctlCmd);

    return 0;
}
