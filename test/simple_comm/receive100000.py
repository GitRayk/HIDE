import socket

SERVER_IP = "2023::3"  # IPv6 loopback address
PORT = 12345
BUFFER_SIZE = 1024
count = 0

# 创建IPv6 UDP套接字
with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as server_socket:
    # 绑定服务器地址
    server_socket.bind((SERVER_IP, PORT))

    print(f"Server listening on port {PORT}...")
    try:
        while True:
            data, client_addr = server_socket.recvfrom(BUFFER_SIZE)
            count = count + 1
    except KeyboardInterrupt:
        print(f'Receive {count} packets')
