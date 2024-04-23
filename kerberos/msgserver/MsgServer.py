import socket
import threading
import struct
from datetime import datetime
from kerberos.utils.enums import RequestEnums, ResponseEnums
from kerberos.utils.utils import is_valid_port, is_valid_ip
from kerberos.utils.structs import RequestStructure, ResponseStructure, Ticket, EncryptedMessage, REQUEST_HEADER_SIZE
from kerberos.utils import decryption as Dec

MSG_FILE_PATH = "C:/git/Kerberos/msgserver/msg.info.txt"

class MsgServer:
    def __init__(self, name: str, ip: str, port: int, max_connections: int = 10, version: int = 24, msg_file_location: str = MSG_FILE_PATH):
        self.name = name
        self.ip = ip 
        self.port = port
        self.id : bytes = None 
        self.__auth_key : bytes = None
        self.__max_connections = max_connections
        self.__version = version
        self.__msg_file_location = msg_file_location

        #files locks
        self.__msg_file_lock = threading.Lock() # Define a lock to manage the threads that attend to msg.info.txt file
        
        #connected clients
        self.clients = {} #key = 'ip:port', value: dict where keys are 'aes_key' and 'id'
    
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
            # Get client info
            ip = client_address[0]
            port = client_address[1]
            client_dict_key = f'{ip}:{port}'
            
            # Receive the message
            data = self.__receive_all(connection, header_size=REQUEST_HEADER_SIZE)  # Assuming 'RequestStructure' header size is fixed at 23 bytes

            # Unpack the received data into a RequestStructure object
            request_obj = RequestStructure.unpack(data)

            # Process the message based on the code
            requestEnum_obj = RequestEnums.find(request_obj.code)
            match requestEnum_obj:
                case RequestEnums.DELIVER_SYMMETRY_KEY: # Receiving Symmetric key from client
                    print("Received delivery of symmetric key request")
                    try:
                        # -- 1 -- Extract from payload 'authenticator' + 'ticket' ---
                        payload = request_obj.payload.encode()
                        
                        # Read lengths of encrypted objects
                        authenticator_length = int.from_bytes(payload[:4], byteorder='little')

                        # Split into encrypted_authenticator and encrypted_ticket parts
                        encrypted_authenticator = payload[4:4 + authenticator_length]
                        encrypted_ticket = payload[4 + authenticator_length:]
                        
                        # -- 2 -- Decrypt 'Ticket' to get the AES_key for the decryption of the authenticator
                        ticket = Ticket.unpack(data=encrypted_ticket,key=self.__auth_key)
                        
                        #verification:
                        if ticket.server_id != self.id:
                            raise ValueError(f"Server's ID does not match the Ticket's ID.")
                        elif datetime.now() > ticket.expiration_time:
                            raise ValueError(f"Ticket has expired")
                        else:

                            # Create client object in dictionary
                            self.clients[client_dict_key] = {
                                'id': ticket.client_id,
                                'key': ticket.aes_key
                            }

                        # -- 3 -- Decrypt authenticator for client's identity verification
                        authenticator = Dec.decrypt_authenticator(data=encrypted_authenticator, client_key=ticket.aes_key)
                        
                        #verification:
                        if authenticator.client_id != ticket.client_id:
                            raise ValueError(f"Ticket's client ID does not match the Authenticator client ID.")
                        elif authenticator.server_id != self.id:
                            raise ValueError(f"Server's ID does not match the Authenticator's ID.")
                        #elif TODO: need to do something with creation time?
                        else:
                            # All Good
                            print(f"Symmetric key from client delivered successfully, connection has been set, ready to receive messages from client {ticket.client_id}.")
                            response = ResponseStructure(self.version, ResponseEnums.SERVER_MESSAGE_ACCEPT_SYMMETRIC_KEY.value, payload=None).pack()
                            connection.sendall(response)
                        
                    except Exception as e:
                        print(f"Stopping delivery of symmetric key process.\t{e}")
                        response = ResponseStructure(self.version, ResponseEnums.SERVER_GENERAL_ERROR.value, payload=None).pack()
                        connection.sendall(response)
                        
                    
                case RequestEnums.MESSAGE_TO_SERVER: # Server Registration (NOTE: BONUS)
                    print("Received print message request")
                    try:
                        # Set parameters
                        payload = request_obj.payload.encode()
                        client = self.clients.get(client_dict_key)
                        if not client:
                            raise ValueError(f"Client '{client_dict_key}' AES key not found. Please deliver AES key before sending a message.")
                        else:
                            client_aes_key = client.get('key')
                            client_id = client.get('id')
                        
                        # Decrypt 'EncryptedMessage' using the AES key with the client
                        message = EncryptedMessage.unpack(data=payload, key=client_aes_key)
                        
                        # Print the message
                        print(f"'{client_id}' |\t{message.message_content}")
                    except Exception as e:
                        print(f"Failed to get message from connection: {client_address}.\t{e}")
                        response = ResponseStructure(self.version, ResponseEnums.SERVER_GENERAL_ERROR.value, payload=None).pack()
                        connection.sendall(response)
                        
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
            self.id = lines[i + 2].strip().encode() #bytes
            if len(self.id) != 16:
                raise ValueError("Server ID must be exactly 16 bytes")
            
            
            self.__auth_key = lines[i + 3].strip().encode() #bytes
            if len(self.__auth_key) != 32:
                raise ValueError("Symmetric key must be exactly 32 bytes")
        return

    # ------- RUN SERVER -------  
    def run_auth_server(self):
        """ Create a TCP/IP socket and run the server"""
        # Initialize the server's parameters
        self.__read_msg_info_file()
        server_address = (self.ip, self.port) 

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