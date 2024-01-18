import socket

SERVER_IP = "2023::1"  # IPv6 loopback address
PORT = 8888
BUFFER_SIZE = 1024

# 创建IPv6 TCP套接字
with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as client_socket:
    # 连接到服务器
    client_socket.connect((SERVER_IP, PORT))

    while True:
        # 从用户输入中获取数据
        message = input("Enter message to send (or 'exit' to quit): ")

        # 检查是否要退出
        if message == 'exit':
            break

        # 发送数据到服务器
        client_socket.sendall(message.encode('utf-8'))

        # 接收服务器的回复
        data = client_socket.recv(BUFFER_SIZE)
        if not data:
            break

        data = data.decode('utf-8')
        print(f"Received from server: {data}")

