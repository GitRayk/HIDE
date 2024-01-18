import socket

SERVER_IP = "2023::1"  # IPv6 loopback address
PORT = 8888
BUFFER_SIZE = 1024

# 创建IPv6 UDP套接字
with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as server_socket:
    # 绑定服务器地址
    server_socket.bind((SERVER_IP, PORT))

    print(f"Server listening on port {PORT}...")

    while True:
        # 接收数据
        data, client_addr = server_socket.recvfrom(BUFFER_SIZE)
        data = data.decode('utf-8')

        # 打印客户端信息和接收到的数据
        print(f"Received from {client_addr}: {data}")

        # 回送相同的数据给客户端
        server_socket.sendto(data.encode('utf-8'), client_addr)

