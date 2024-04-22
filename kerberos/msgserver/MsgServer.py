import socket
import threading
import uuid
import struct
from datetime import datetime, timedelta
from kerberos.utils.enums import RequestEnums, ResponseEnums
from kerberos.utils.utils import read_port, update_txt_file, read_txt_file, is_valid_port, is_valid_ip
from kerberos.utils.structs import RequestStructure, ResponseStructure ,Client, Server, EncryptedKey, Ticket, SymmetricKeyResponse, RESPONSE_HEADER_SIZE, REQUEST_HEADER_SIZE, ServerInList
from kerberos.utils.encryption import generate_aes_key, generate_random_iv, derive_encryption_key

MSG_FILE_PATH = "C:/git/Kerberos/msgserver/msg.info.txt"

class MsgServer:
    def __init__(self, name: str, ip: str, port: int, max_connections: int = 10, version: int = 1, msg_file_location: str = MSG_FILE_PATH):
        self.name = name
        self.ip = ip 
        self.port = port
        self.id = None 
        self.__auth_key = None
        self.__max_connections = max_connections
        self.__version = version
        self.__msg_file_location = msg_file_location

        #files locks
        self.__msg_file_lock = threading.Lock() # Define a lock to manage the threads that attend to msg.info.txt file
        
        #connected clients
        self.clients = {} #key = client_id, value = aes_key
    
    # ---- GETS ----
    @property
    def version(self):
        return self.__version
    
    @property
    def max_connections(self):
        return self.__max_connections
    
    @property
    def msg_file(self):
        return self.__msg_file_location
    
    @property
    def msg_file_lock(self):
        return self.__msg_file_lock

    
    
    def __receive_all(self, connection: socket.socket, header_size: int) -> bytes:
        """
        Helper function to receive all data from a socket connection matching the format of 'RequestStructure'.

        Args:
            connection (socket.socket): opened connection
            header_size (int): header size

        Returns:
            bytes: The complete data from the connection
        """
        data = b''
        while len(data) < header_size:
            chunk = connection.recv(header_size - len(data))
            if not chunk:
                raise RuntimeError("Incomplete header data received.")
            data += chunk
        
        # Parse header to determine payload size
        client_id, version, code, payload_size = struct.unpack('<16s1s2sI', data)
        payload_size = int(payload_size)
        
        # Receive the payload
        data += self.__receive_all(connection, payload_size)

        return data

    #TODO: STOPPED HERE
    def __handle_client(self, connection: socket.socket, client_address: tuple[str, int]):
        """
        Function to handle communication with a single client.
        """
        print(f"Connection from {client_address}")

        try:
            # Receive the message
            data = self.__receive_all(connection, header_size=REQUEST_HEADER_SIZE)  # Assuming 'RequestStructure' header size is fixed at 23 bytes

            # Unpack the received data into a RequestStructure object
            request_obj = RequestStructure.unpack(data)

            # Process the message based on the code
            requestEnum_obj = RequestEnums.find(request_obj.code)
            match requestEnum_obj:
                case RequestEnums.CLIENT_REGISTRATION: # Client Registration
                    print("Received client registration request:")
                    print("Payload:", request_obj.payload)
                    
                    pass
                case RequestEnums.SERVER_REGISTRATION: # Server Registration (NOTE: BONUS)
                    print("Received server registration request:")
                    print("Payload:", request_obj.payload)
                    
                    pass
                    
                case _:
                    print(f"Unfamiliar request code: '{request_obj.code}'")
                    response = ResponseStructure(self.version, ResponseEnums.SERVER_GENERAL_ERROR.value, payload=None).pack()
                    connection.sendall(response)
        finally:
            # Clean up the connection
            connection.close()
    
    # ------- Utility functions -------
    def __read_msg_info_file(self) -> None:
        """
        Private function to read msg.info file and initialize self parameters

        Returns:
            list[Server]: list of Server objects that were extracted from file
        """
        servers = []
        # Acquire the lock before reading from the file
        with self.msg_file_lock:
            with open(self.msg_file, 'r') as file:
                lines = file.readlines()
        # Release the lock as soon as the file reading is done
        # Now we have the data and can process it without holding the lock
        num_lines = len(lines)
        for i in range(0, num_lines, 4):
            
            #get ip, port and validate
            ip_port = lines[i].strip().split(':')
            self.ip = ip_port[0]
            self.port = int(ip_port[1])
            if not is_valid_ip(self.ip):
                raise ValueError(f"Invalid IP address format")
            if not is_valid_port(self.port):
                raise ValueError(f"The port number '{self.port}' is not valid. Please provide a valid port number between 0 and 65535.")
            
            #get server name
            self.name = lines[i + 1].strip()
            if not 1 <= len(self.name) <= 255:
                raise ValueError(f"Server's name must be at least 1 char and up to 255 chars")
            
            #get server id
            self.id = lines[i + 2].strip()
            if len(self.id) != 16:
                raise ValueError("Server ID must be exactly 16 bytes")
            
            
            self.__auth_key = lines[i + 3].strip()
            if len(self.__auth_key) != 32:
                raise ValueError("Symmetric key must be exactly 32 bytes")
        return

    # ------- RUN SERVER -------  
    def run_auth_server(self):
        """ Create a TCP/IP socket and run the server"""
        # Initialize the server's parameters
        self.__read_msg_info_file()
        server_address = (self.ip, self.port) 
        
        #
        

        # Craeete and bind the socket to the port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("starting up on '%s' port '%s'" %server_address)
        sock.bind(server_address)

        sock.listen(self.max_connections)

        try:
            while True:
                # Wait for a connection
                print('Waiting for a connection')
                connection, client_address = sock.accept()

                # Start a new thread to handle the client
                client_thread = threading.Thread(target=self.__handle_client, args=(connection, client_address))
                client_thread.start()

        finally:
            # Clean up the server socket
            sock.close()