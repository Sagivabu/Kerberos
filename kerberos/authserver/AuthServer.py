import socket
import sys
import threading
from utils.utils import read_port
from utils.structs import Request, Response

PORT_FILE_PATH = "C:\git\Kerberos\AuthServer\port.info.txt"

class AuthServer:
    def __init__(self, server_name: str = "localhost", server_default_port: int = 1256, server_connections: int = 10):
        self.server_name = server_name 
        self.server_default_port = server_default_port
        self.__server_connections = 10
        
                    
    def __receive_all(connection, size):
        """
            Helper function to receive all data from a socket connection.
        """
        data = b''
        while len(data) < size:
            chunk = connection.recv(size - len(data))
            if not chunk:
                raise RuntimeError("Incomplete data received.")
            data += chunk
        return data

    
    @property
    def connections(self):
        return self.__server_connections
    
    # Create a TCP/IP socket
    def run_auth_server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Bind the socket to the port
        port = read_port(PORT_FILE_PATH, self.server_default_port)
        server_address = (self.server_name, port)
        print("starting up on '%s' port '%s'" %server_address)
        sock.bind(server_address)

        sock.listen(self.__server_connections)
        
        while True:
            # Wait for a connection
            print('Waiting for a connection')
            connection, client_address = sock.accept()
            print(f"Connection from {client_address}")
            

            try:
                # Receive the message
                data = self.__receive_all(connection, 23)  # Assuming header size is fixed at 23 bytes (following the payload protocol class)

                # Process the message
                payload_obj = Request.unpack(data)
                
                # Process the message based on the code
                if payload_obj.code == "RG":  # Registration request
                    print("Received registration request:")
                    print("Client ID:", payload_obj.client_id)
                    print("Version:", payload_obj.version)
                    print("Payload:", payload_obj.payload)
                    # Process registration request...
                elif payload_obj.code == "CN":  # Connection request
                    print("Received connection request:")
                    print("Client ID:", payload_obj.client_id)
                    print("Version:", payload_obj.version)
                    print("Payload:", payload_obj.payload)
                    # Process connection request...
                else:
                    print("Unknown request code")

            finally:
                # Clean up the connection
                connection.close()
