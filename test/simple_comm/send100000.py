import socket
import time
 
# 目标IPv6地址和端口
dest_ip = '2023::3'
dest_port = 12345
 
# 创建IPv6的UDP套接字
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
 
# 定义要发送的数据
data = b'Hello'
total_packets = 100000
 
start_time = time.time()
try:
    for i in range(total_packets):
        # 发送数据
        sock.sendto(data, (dest_ip, dest_port))

 
except KeyboardInterrupt:
    print("程序被用户中断")
 
finally:
    end_time = time.time()
    sock.close()
    total_time = end_time - start_time
    speed = total_packets / total_time

    print("total time: %fs" % (total_time))
    print("average: %.2f packets/s, %.2f bytes/s" % (speed, speed * (67)))