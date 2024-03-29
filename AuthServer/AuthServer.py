import socket
import sys
import threading
from utils import read_port

PORT_FILE_PATH = "port.info.txt"
AUTH_SERVER_HOST_NAME = "localhost" #127.0.0.1

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the port
server_address = (AUTH_SERVER_HOST_NAME, read_port(PORT_FILE_PATH))
print('starting up on %s port %s' %server_address)
sock.bind(server_address)

sock.listen(1)

while True:
    # Wait for a connection
    print('waiting for a connection')
    connection, client_address = sock.accept()


    try:
        print(f"connection from {client_address}")

        # Receive the data in small chunks and retransmit it
        while True:
            data = connection.recv(16)
            print(f"received '{data}'")
            if data:
                print(f"sending data back to the client")
                connection.sendall(data)
            else:
                print(f"no more data from {client_address}")
                break
            
    finally:
        # Clean up the connection
        connection.close()