import socket
import threading
import struct
import base64
import uuid
import os
from datetime import datetime
from kerberos.utils.enums import RequestEnums, ResponseEnums
from kerberos.utils.utils import is_valid_port, is_valid_ip
from kerberos.utils.structs import RequestStructure, ResponseStructure, Ticket, EncryptedMessage, REQUEST_HEADER_SIZE, RESPONSE_HEADER_SIZE
from kerberos.utils import decryption as Dec
from kerberos.utils import encryption as Enc

MSG_FILE_NAME = "msg.info.txt"

class MsgServer:
    def __init__(self, max_connections: int = 10, version: int = 24):
        self.name : str
        self.ip : str
        self.port : int
        self.id : bytes 
        self.__auth_key : bytes
        self.__max_connections = max_connections
        self.__version = version
        
        # Create the file path
        current_directory = os.path.dirname(__file__) # Get the directory of the current Python script
        self.__msg_file_location = os.path.join(current_directory, MSG_FILE_NAME)

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
    
    def __receive_all_response(self, connection: socket.socket, header_size: int) ->bytes:
        """
        Helper function to receive all data from a socket connection matching the format of 'ResponseStructure'.

        Args:
            connection (socket.socket): opened connection
            header_size (int): header size

        Returns:
            bytes: The complete data from the connection
        """
        try:
            # Receive the header first
            header_data = b''
            while len(header_data) < header_size:
                chunk = connection.recv(header_size - len(header_data))
                if not chunk:
                    raise RuntimeError("Incomplete header data received.")
                header_data += chunk
            
            # Unpack the header to determine payload size
            version, code, payload_size = struct.unpack('<B2sI', header_data)
            payload_size = int(payload_size)
            
            # Receive the payload
            payload_data = b''
            while len(payload_data) < payload_size:
                chunk = connection.recv(payload_size - len(payload_data))
                if not chunk:
                    raise RuntimeError("Incomplete payload data received.")
                payload_data += chunk

            return header_data + payload_data
        except Exception as e:
            raise

    def __receive_all_request(self, connection: socket.socket, header_size: int) -> bytes:
        """
        Helper function to receive all data from a socket connection matching the format of 'RequestStructure'.

        Args:
            connection (socket.socket): opened connection
            header_size (int): header size

        Returns:
            bytes: The complete data from the connection
        """
        try:
            # Receive the header first
            header_data = b''
            while len(header_data) < header_size:
                chunk = connection.recv(header_size - len(header_data))
                if not chunk:
                    raise RuntimeError("Incomplete header data received.")
                header_data += chunk
            
            # Unpack the header to determine payload size
            client_id, version, code, payload_size = struct.unpack('<16sBHI', header_data)
            payload_size = int(payload_size)
            
            # Receive the payload
            payload_data = b''
            while len(payload_data) < payload_size:
                chunk = connection.recv(payload_size - len(payload_data))
                if not chunk:
                    raise RuntimeError("Incomplete payload data received.")
                payload_data += chunk

            return header_data + payload_data
        except Exception as e:
            raise

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
            data = self.__receive_all_request(connection, header_size=REQUEST_HEADER_SIZE)  # Assuming 'RequestStructure' header size is fixed at 23 bytes

            # Unpack the received data into a RequestStructure object
            request_obj = RequestStructure.unpack(data)

            # Process the message based on the code
            requestEnum_obj = RequestEnums.find(request_obj.code)
            match requestEnum_obj:
                case RequestEnums.DELIVER_SYMMETRY_KEY: # Receiving Symmetric key from client
                    print("Received delivery of symmetric key request")
                    try:
                        if not request_obj.payload:
                            raise ValueError(f"Delivery of Symmetric Key must conatin data in the payload")
                        
                        # -- 1 -- Extract from payload 'authenticator' + 'ticket' ---
                        payload = request_obj.payload
                        
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
                            print(f"Symmetric key from client delivered successfully, connection has been set, ready to receive messages from client {ticket.client_id.hex()}.")
                            response = ResponseStructure(self.version, ResponseEnums.SERVER_MESSAGE_ACCEPT_SYMMETRIC_KEY.value, payload=None).pack()
                            connection.sendall(response)
                        
                    except Exception as e:
                        print(f"Stopping delivery of symmetric key process.\t{e}")
                        response = ResponseStructure(self.version, ResponseEnums.SERVER_GENERAL_ERROR.value, payload=None).pack()
                        connection.sendall(response)
                        
                case RequestEnums.MESSAGE_TO_SERVER: # Print Message request
                    print("Received print message request")
                    try:
                        if not request_obj.payload:
                            raise ValueError(f"Print message request must conatin data in the payload")
                        
                        # Set parameters
                        payload = request_obj.payload
                        client = self.clients.get(client_dict_key)
                        if not client:
                            raise ValueError(f"Client '{client_dict_key}' AES key not found. Please deliver AES key before sending a message.")
                        else:
                            client_aes_key = client.get('key')
                            client_id = client.get('id')
                        
                        # Decrypt 'EncryptedMessage' using the AES key with the client
                        message = EncryptedMessage.unpack(data=payload, aes_key=client_aes_key)
                        
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
            print(f"Close connection with {client_address} server.")
            connection.close()
    
    # ------- Utility functions -------
    def __read_msg_info_file(self) -> None:
        """
        Private function to read msg.info file and initialize self parameters

        Returns:
            list[Server]: list of Server objects that were extracted from file
        """
        # Acquire the lock before reading from the file
        with self.msg_file_lock:
            with open(self.msg_file, 'r') as file:
                lines = file.readlines()
        # Release the lock as soon as the file reading is done
        # Now we have the data and can process it without holding the lock
        
        #validate msg.info format
        num_lines = len(lines)
        if num_lines != 4:
            raise ValueError(f"File is not in the accepted format:\nip:port\nserver_name\nserver_id\naes_key_to_auth_server\n")
            
        #get ip, port and validate
        ip_port = lines[0].strip().split(':')
        self.ip = ip_port[0]
        self.port = int(ip_port[1])
        if not is_valid_ip(self.ip):
            raise ValueError(f"Invalid IP address format")
        if not is_valid_port(self.port):
            raise ValueError(f"The port number '{self.port}' is not valid. Please provide a valid port number between 0 and 65535.")
        
        #get server name
        self.name = lines[1].strip()
        if not 1 <= len(self.name) <= 255:
            raise ValueError(f"Server's name must be at least 1 char and up to 255 chars")
        
        #get server id
        id_str = lines[2].strip()
        self.id = bytes.fromhex(id_str)
        if len(self.id) != 16:
            raise ValueError("Server ID must be exactly 16 bytes")
        
        
        auth_key_str = lines[3].strip()
        self.__auth_key = base64.b64decode(auth_key_str)
        if len(self.__auth_key) != 32:
            raise ValueError("Symmetric key must be exactly 32 bytes")
        return

    def build_server_reg_payload(self) -> bytes:
        """
        Build the payload for registration process

        Returns:
            bytes: payload = name + \x00 + auth_aes_key
        """
        try:
            # Concatenate name and auth key with null-terminated characters
            payload = self.name.encode() + b'\x00' + self.__auth_key
            return payload
        except Exception as e:
            raise Exception(f"Failed to build registration request payload with name and aes_key for auth server.\t{e}")
        
    def register_server(self, ip: str, port: int) -> bool:
        """ Register this server to Authentication server

        Args:
            ip (str): Authentication server's ip
            port (int): Authentication server's port


        Returns:
            bool: True if registration succeed, otherwise False
        """
        try:
            # Create the Registration Request
            reg_payload = self.build_server_reg_payload()
            fake_id = bytes.fromhex((uuid.uuid4()).hex)
            request = RequestStructure(client_id=fake_id, #NOTE: first ID doesnt matter
                                       version=self.version,
                                       code=RequestEnums.SERVER_REGISTRATION.value,
                                       payload=reg_payload).pack()
            
            # Create a socket object
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Bind the client socket to the desired port
            client_socket.bind(('0.0.0.0', self.port))
            
            # Connect to the server
            client_socket.connect((ip, port))

            # Send data to the server
            client_socket.sendall(request)

            # Receive response from the server
            response_data = self.__receive_all_response(client_socket, header_size=RESPONSE_HEADER_SIZE)  # Assuming 'ResponseStructure' header size is fixed at 7 bytes
            
            # Unpack the received data into a ResponseStructure object
            response_obj = ResponseStructure.unpack(response_data)
            
            # Process the message based on the code
            responseEnum_obj = ResponseEnums.find(response_obj.code)
            match responseEnum_obj:
                case ResponseEnums.REGISTRATION_SUCCESS:
                    if not response_obj.payload:
                        raise ValueError(f"Registration response must contain ID as a payload")
                    if len(response_obj.payload) != 16:
                        raise ValueError(f"Server ID that was send from Auth server must be 16 bytes long")
                    self.id = response_obj.payload
                    print(f"Registration Process complete succefully")
                    return True
                case ResponseEnums.REGISTRATION_FAILED:
                    raise ValueError(f"Authentication Server returned ERROR")
                case ResponseEnums.REGISTRATION_USER_EXISTS:
                    raise ValueError(f"Failed to register new server. Server's name '{self.name}' already exists in DB.")
                case _:
                    raise ValueError(f"Unfamiliar response code: '{response_obj.code}'")

        except Exception as e:
            print(f"Registration Process failed, please try again.\t{e}")
            return False
        
    def __create_info_file(self):
        """
        Write server information to a text file.

        Args:
            server_ip (str): The server's IP address.
            server_port (int): The server's port number.
            server_name (str): The server's name.
            server_id (str): The server's unique ID.
            server_aes_key (bytes): The server's AES key.
            file_path (str): The path to the text file to write the information to.
        """
        with open(self.msg_file, 'w') as file:
            file.write(f"{self.ip}:{self.port}\n")
            file.write(f"{self.name}\n")
            id_str = self.id.hex()
            file.write(f"{id_str}\n")
            aes_key_base64 = base64.b64encode(self.__auth_key).decode('utf-8')
            file.write(f"{aes_key_base64}\n")
    
    # ------- RUN SERVER -------  
    def run(self):
        """ Create a TCP/IP socket and run the server"""
        
        # Register to Msg server
        to_register = input("If you want to register a new server, please insert 'Y', otherwise it will look for msg.info.txt file to read data from: ")
        
        # Register a new server
        if to_register in ['Y','y']:
            try:
                # -- 1 -- Get Msg server info
                auth_server_ip = input("Enter Authentication server IP: ") # Authentication server IP
                if not is_valid_ip(auth_server_ip):
                    print(f"Invalid IP for Authentication server.")
                    return
                
                auth_server_port = input("Enter Authentication server PORT: ") # Authentication server port
                if not is_valid_port(auth_server_port):
                    print(f"Invalid Port for Authentication server.")
                    return
                
                # -- 2 -- Get Server info
                server_ip = input("Enter this server IP: ") # Get server IP
                if not is_valid_ip(server_ip):
                    print(f"Invalid IP for server.")
                    return
                else: self.ip = server_ip
                
                server_port = input("Enter this server PORT: ") # Get server port
                if not is_valid_port(server_port):
                    print(f"Invalid Port for server.")
                    return
                else: self.port = int(server_port)
                
                server_name = input("Enter this server Name: ") # Get server name
                if not 1 <= len(server_name) <= 255:
                    print(f"Server's name must be up to 255 chars.")
                    return
                else: self.name = server_name
                
                self.__auth_key = Enc.generate_aes_key() # Generate AES KEY
                
                # -- 3 -- Register the server
                if not self.register_server(auth_server_ip, int(auth_server_port)):
                    return
                
                # -- 4 -- Create msg.info.txt file
                self.__create_info_file()
            except Exception as e:
                print(f"Failed to register server in Message server.\t{e}")
                return
            
        # Read server from file
        else:
            try:
                # Initialize the server's parameters
                self.__read_msg_info_file()
            except Exception as e:
                print(f"Failed to read msg.info txt file: {e}")
                return


        # Craeete and bind the socket to the port
        server_address = (self.ip, self.port)
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
            print(f"Server's TCP socket is closing.")
            sock.close()
            
            
# ------ RUN THE SERVER ------
if __name__ == "__main__":
    msg_server = MsgServer()
    msg_server.run()