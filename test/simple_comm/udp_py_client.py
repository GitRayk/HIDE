import socket

SERVER_IP = "2023::1"  # IPv6 loopback address
PORT = 8888
BUFFER_SIZE = 1024

# 创建IPv6 UDP套接字
with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as client_socket:
    while True:
        # 从用户输入中获取数据
        message = input("Enter message to send (or 'exit' to quit): ")

        # 检查是否要退出
        if message == 'exit':
            break

        # 发送数据到服务器
        client_socket.sendto(message.encode('utf-8'), (SERVER_IP, PORT))

        # 接收服务器的回复
        data, server_addr = client_socket.recvfrom(BUFFER_SIZE)
        data = data.decode('utf-8')

        # 打印接收到的数据
        print(f"Received from server {server_addr}: {data}")

