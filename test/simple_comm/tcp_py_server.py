import socket

SERVER_IP = "2023::1"  # IPv6 loopback address
PORT = 8888
BUFFER_SIZE = 1024

# 创建IPv6 TCP套接字
with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as server_socket:
    # 绑定服务器地址
    server_socket.bind((SERVER_IP, PORT))
    
    # 监听连接
    server_socket.listen()

    print(f"Server listening on port {PORT}...")

    # 接受连接
    client_socket, client_addr = server_socket.accept()

    with client_socket:
        print(f"Connection from {client_addr}")

        while True:
            # 接收数据
            data = client_socket.recv(BUFFER_SIZE)
            if not data:
                break

            data = data.decode('utf-8')
            print(f"Received from {client_addr}: {data}")

            # 发送相同的数据回客户端
            client_socket.sendall(data.encode('utf-8'))

