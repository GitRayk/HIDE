# 项目说明
该项目编译成模块使用扩展报头实现对数据包源IPv6地址的加密处理，并且在传输路径的每一跳上都会进行加解密  

对源地址加解密时使用对称密钥，要求每两个设备（不论是中间路由还是端设备）都有对称密钥  

## 项目结构
* extended_header：包括了与扩展报头相关的定义、向数据包中添加扩展报头的具体实现  
* input：实现了在 pre_routing 节点处增加钩子函数来处理收到的数据包  
* out：实现了在 post_routing 节点处增加钩子函数来处理发出的数据包  
* hash_table：维护实现以上功能的哈希表并提供相应的操作接口  
* kern_aes：实现 AES 对称密钥加密算法  
* kern_hash：实现哈希运算  
* kern_ioctl：通过字符设备文件实现从用户空间接受下发的命令（下发设备参数）并进行处理  
* ioctl_cmd：定义了用户空间与内核模块交互的通用信息格式  

## 部署说明
按以下顺序执行：  

创建设备文件： `sudo mknod /dev/labelCmd c 168 0`  
编译该项目：`make all`  
插入内核模块：`sudo insmod extended.ko`

## 测试说明
### 测试环境1
主机 A 与路由器 R 直接连接  
A 的网卡配置为:  
```
ipv6: 2023::2
mac: 00:0c:29:83:1a:20
```

R 的网卡配置为:  
```
ipv6: 2023::1
mac: 00:0c:29:c2:86:18
```

### 测试步骤
对主机 A：  
1. 将 test/wireshark_plugins 目录下的 wireshark 插件脚本 ALHdissector.lua 放到 wireshark 指定的目录中  
2. 编译 test/app_*.c，编译后分别运行程序，其中 A 对应的程序为 app_a，R 对应的程序为 app_b
    ``` shell
    gcc ./test/app_a.c -o ./test/app_a -I./include && ./test/app_a
    ```
3. (option) 手动将邻居表的表项添加为永久有效
    ``` shell
    sudo ip neigh change 2023::1 lladdr 00:0c:29:c2:86:18 dev ens34
    ```
4. 运行 test/simple_comm 中的 python 文件进行 udp、tcp测试
    ``` shell
    python3 tcp_py_client.py
    python3 udp_py_client.py
    ```
5. 使用 wireshark 抓包观察数据