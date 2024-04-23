import socket
import threading
import uuid
import struct
from datetime import datetime, timedelta
from kerberos.utils.enums import RequestEnums, ResponseEnums
from kerberos.utils.utils import read_port, update_txt_file, read_txt_file, is_valid_port
from kerberos.utils.structs import RequestStructure, ResponseStructure ,Client, Server, EncryptedKey, Ticket, SymmetricKeyResponse, REQUEST_HEADER_SIZE, ServerInList
from kerberos.utils.encryption import generate_aes_key, generate_random_iv, derive_encryption_key


PORT_FILE_PATH = "C:/git/Kerberos/AuthServer/port.info.txt"
MSG_FILE_PATH = "C:/git/Kerberos/AuthServer/msg.info.txt"
CLIENTS_FILE_PATH = "C:/git/Kerberos/AuthServer/clients.txt"

class AuthServer:
    def __init__(self, server_name: str = "localhost", \
                server_default_port: int = 1256, \
                server_connections: int = 10, \
                port_file_location: str = PORT_FILE_PATH, \
                msg_file_location: str = MSG_FILE_PATH, \
                clients_file_location: str = CLIENTS_FILE_PATH,
                version: int = 24):
        self.server_name = server_name 
        self.server_default_port = server_default_port
        self.__server_max_connections = server_connections
        self.__port_file_location = port_file_location
        self.__msg_file_location = msg_file_location
        self.__clients_file_location = clients_file_location
        self.__ticket_expiration_time: timedelta = timedelta(hours=1)
        self.__version = version

        #files locks
        self.__client_file_lock = threading.Lock() # Define a lock to manage the threads that attend to clients.txt file. NOTE: the lock is per instance of the class!
        self.__msg_file_lock = threading.Lock() # Define a lock to manage the threads that attend to msg.info.txt file
       
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
                    
                    try:
                        client_name, client_password = request_obj.extract_name_password()
                    except Exception as e: #if 
                        print(f"Failed to extract name and password from given payload.\t{e}")
                        response = ResponseStructure(self.version, ResponseEnums.REGISTRATION_FAILED.value, payload=None).pack() #prepare response as bytes
                        connection.sendall(response)
                    else:
                        if not self.__is_client_exist_by_name(client_name): #if client not exists in list
                            try:
                                # Create new 'Client' object
                                new_uuid = str(uuid.uuid4())
                                new_client = Client.from_plain_password(new_uuid, client_name, client_password, datetime.now())
                                
                                #add it to clients.txt file
                                self.__add_new_client_to_file(new_client)

                                #send success response
                                response = ResponseStructure(self.version, ResponseEnums.REGISTRATION_SUCCESS.value, new_uuid).pack() #prepare response as bytes
                                connection.sendall(response)
                                
                            except Exception as e:
                                print(f"Failed to register new client with name: '{client_name}', password: '{client_password}'.\n{e}")
                                response = ResponseStructure(self.version, ResponseEnums.REGISTRATION_FAILED.value, None).pack() #prepare response as bytes
                                connection.sendall(response)
                        else:
                            print(f"Failed to register new client, name '{client_name}' already exists in DB.")
                            response = ResponseStructure(self.version, ResponseEnums.REGISTRATION_USER_EXISTS.value, None).pack() #prepare response as bytes
                            connection.sendall(response)
                    
                case RequestEnums.SERVER_REGISTRATION: # Server Registration (NOTE: BONUS)
                    print("Received server registration request:")
                    print("Payload:", request_obj.payload)
                    
                    try:
                        server_name, server_symmetric_key = request_obj.extract_server_name_symmetric_key()
                    except Exception as e: #if 
                        print(f"Failed to extract name and symmetric key from given payload.\t{e}")
                        response = ResponseStructure(self.version, ResponseEnums.REGISTRATION_FAILED.value, payload=None).pack() #prepare response as bytes
                        connection.sendall(response)
                    else:
                        if not self.__is_server_exist_by_name(server_name): #if server does not exists in list
                            try:
                                # Create new 'Server' object
                                new_uuid = str(uuid.uuid4()) #create uuid
                                client_ip, client_port = client_address #get the server IP and PORT
                                new_server = Server(server_ip=client_ip,
                                                    server_port=client_port,
                                                    server_name=server_name,
                                                    server_id=new_uuid,
                                                    symmetric_key=server_symmetric_key)
                                
                                if self.__is_ip_port_in_use(client_ip, client_port): #NOTE: XXX: Can remove this if you dont want this validation
                                    raise ValueError(f"Server with IP address {client_ip} and port {client_port} is already in use.")
                                
                                #add it to msg.info.txt file
                                self.__add_server_to_file(new_server)

                                #send success response
                                response = ResponseStructure(self.version, ResponseEnums.REGISTRATION_SUCCESS.value, new_uuid).pack() #prepare response as bytes
                                connection.sendall(response)
                                
                            except Exception as e:
                                print(f"Failed to register new server with name: '{server_name}', symmetric_key: '{server_symmetric_key}'.\n{e}")
                                response = ResponseStructure(self.version, ResponseEnums.REGISTRATION_FAILED.value, None).pack() #prepare response as bytes
                                connection.sendall(response)
                        else:
                            print(f"Failed to register new server, name '{server_name}' already exists in DB.")
                            response = ResponseStructure(self.version, ResponseEnums.REGISTRATION_FAILED.value, None).pack() #prepare response as bytes
                            connection.sendall(response)

                case RequestEnums.SERVER_LIST: # Server List (NOTE: BONUS)
                    print("Received servers list request:")     
                    try:
                        #check if client registered
                        if not self.__is_client_exist_by_id(request_obj.client_id):
                            print(f"ERROR: Client is not registered in DB, request rejected.")
                            response = ResponseStructure(self.version, ResponseEnums.SERVER_REJECT_REQUEST.value, payload=None).pack() #prepare response as bytes
                            connection.sendall(response)
                            
                        #get list of servers
                        server_list = self.__read_server_file()
                        response_bytes = self.build_servers_list(server_list)
                        response = ResponseStructure(self.version, ResponseEnums.SERVER_LIST.value, payload=response_bytes).pack() #prepare response as bytes
                        connection.sendall(response)
                    except Exception as e: #if 
                        print(f"Failed to get list of servers.\t{e}")
                        response = ResponseStructure(self.version, ResponseEnums.SERVER_GENERAL_ERROR.value, payload=None).pack() #prepare response as bytes
                        connection.sendall(response)

                case RequestEnums.SYMMETRIC_KEY: # Symmetric key to connect a server
                    print("Received Symmetric key to a server request:")
                    print("Payload:", request_obj.payload)
                    
                    try:
                        #check if client registered
                        if not self.__is_client_exist_by_id(request_obj.client_id):
                            print(f"ERROR: Client is not registered in DB, request rejected.")
                            response = ResponseStructure(self.version, ResponseEnums.SERVER_REJECT_REQUEST.value, payload=None).pack() #prepare response as bytes
                            connection.sendall(response)
                    except:
                        print(f"Failed to identify the client by his ID")
                        response = ResponseStructure(self.version, ResponseEnums.SERVER_GENERAL_ERROR.value, payload=None).pack() #prepare response as bytes
                        connection.sendall(response)
                    try: #get request's payload
                        server_id, nonce = request_obj.extract_server_id_nonce()
                    except Exception as e: #if 
                        print(f"Failed to extract server_id and nonce from given payload.\t{e}")
                        response = ResponseStructure(self.version, ResponseEnums.SERVER_GENERAL_ERROR.value, payload=None).pack() #prepare response as bytes
                        connection.sendall(response)
                    else:

                        # Create client and server lists
                        server_list = self.__read_server_file() #get all servers from db
                        client_list = self.__read_clients_file() #get all clients from db

                        # Create the reuqester Client object and  required Server object
                        the_client = Client.find_client(client_list, request_obj.client_id)
                        the_server = Server.find_server(server_list, server_id)

                        # If server not found return error
                        if not the_server:
                            print(f"Failed to find required server in DB following given server_id: '{server_id}'. Server may not be exist.")
                            response = ResponseStructure(self.version, ResponseEnums.SERVER_GENERAL_ERROR.value, payload=None).pack() #prepare response as bytes
                            connection.sendall(response)
                        
                        # If Client not found return error (Can happen only in case the client is not registered in DB)
                        elif not the_client:
                            print(f"Failed to find the client information in DB following client_id from request header: '{request_obj.client_id}'. Client may not be registered.")
                            response = ResponseStructure(self.version, ResponseEnums.SERVER_GENERAL_ERROR.value, payload=None).pack() #prepare response as bytes
                            connection.sendall(response)
                        
                        # Prepare the response with the server's information
                        else: 
                            #--1-- Generate AES_key for the server-client communication
                            AES_key = generate_aes_key()
                            
                            #--2-- Create 'EncryptedKey' object 
                            encrypted_key_iv = generate_random_iv()
                            client_key = derive_encryption_key(the_client.password_hash) # Derive client key based on the client's password_hash
                            packed_encrypted_key = EncryptedKey(iv=encrypted_key_iv,
                                                         nonce=nonce,
                                                         aes_key=AES_key).pack(client_key)
                            
                            #--3-- Create 'Ticket' object
                            ticket_iv = generate_random_iv()
                            msg_server_key = derive_encryption_key(the_server.symmetric_key.encode())
                            creation_time = datetime.now()
                            expiration_time = creation_time + self.ticket_expiration_time
                            packed_ticket = Ticket(server_version=self.version,
                                            client_id=the_client.id,
                                            server_id=the_server.server_id,
                                            creation_time=creation_time,
                                            ticket_iv=ticket_iv,
                                            aes_key=AES_key,
                                            expiration_time=expiration_time).pack(msg_server_key)
                            
                            #--4-- Prepare the SymmetricKeyResponse object
                            SKR_response = SymmetricKeyResponse(client_id=the_client.id, encrypted_key=packed_encrypted_key, ticket=packed_ticket)
                            
                            #--5-- Send response
                            response = ResponseStructure(self.version, ResponseEnums.SYMMETRIC_KEY.value, payload=SKR_response).pack() #prepare response as bytes
                            connection.sendall(response)
                    
                case _:
                    print(f"Unfamiliar request code: '{request_obj.code}'")
                    response = ResponseStructure(self.version, ResponseEnums.SERVER_GENERAL_ERROR.value, payload=None).pack()
                    connection.sendall(response)
        finally:
            # Clean up the connection
            connection.close()
     
    # ------- Client handle Functions -------
    def __add_new_client_to_file(self, client_obj: Client) -> None:
        """
        Update the clients.txt file with new client info (new row)

        Args:
            client_obj (Client): info about client
        """
        with self.client_file_lock:
            update_txt_file(self.clients_file, client_obj.print_as_row() + "\n")
              
    def  update_client_info(self, client_obj: Client):
        """
        Replace the 'lastseen' value in a row with a new value in the text file.

        Args:
            client_obj (Client): The Client object containing the id, name, and password_hash to search for.
        """
        try:
            # Convert id, name, and password_hash to strings
            id_str = client_obj.id.decode('utf-8')
            name_str = client_obj.name
            password_hash_str = client_obj.password_hash.hex()

            # Read the content of the text file
            with self.client_file_lock:
                with open(self.clients_file, 'r') as file:
                    lines = file.readlines()

            # Find and replace the lastseen value in the row
            for i, line in enumerate(lines):
                line_parts = line.strip().split(': ')
                if (
                    id_str == line_parts[0] and
                    name_str == line_parts[1] and
                    password_hash_str == line_parts[2]
                ):
                    # Reconstruct the line with updated lastseen
                    lines[i] = client_obj.print_as_row()
                    break
                
            # Write the modified content back to the file
            with self.client_file_lock:
                with open(self.clients_file, 'w') as file:
                    file.writelines(lines)
                
        except Exception as e:
            print(f"Failed to update client info:\t'{client_obj}'")
            raise

    def __read_clients_file(self) -> list[Client]:
        """
        Private function to read clients file and return list of clients from file

        Returns:
            list[Client]: list of Client objects that were extracted from file
        """
        with self.client_file_lock: #read file with lock premit
            content = read_txt_file(self.clients_file)
        
        client_list = []
        for line in content.split('\n'):
            if line.strip():  # Check if line is not empty
                client_info = line.split(': ')
                id, name, password_hash_str, date_time_str = client_info
                password_hash = bytes.fromhex(password_hash_str)  # Convert hexadecimal string to bytes
                date_time = datetime.strptime(date_time_str, '%Y-%m-%d %H:%M:%S')  # Parse datetime string
                client = Client(id, name, password_hash, date_time)
                client_list.append(client)
        return client_list

    def __is_client_exist_by_name(self, client_name: str) -> bool:
        """
        Return True if client_name exists in client.txt

        Args:
            client_name (str): Client's name

        Returns:
            bool: True if exists, False otherwise
        """
        client_list = self.__read_clients_file()
        for client in client_list:
            if client.name == client_name:
                return True
        return False

    def __is_client_exist_by_id(self, client_id: str) -> bool:
        """
        Return True if client_id exists in client.txt

        Args:
            client_id (str): Client's id

        Returns:
            bool: True if exists, False otherwise
        """
        client_list = self.__read_clients_file()
        for client in client_list:
            if client.id == client_id:
                return True
        return False
    
    # ------- Server handle Functions -------
    def __add_server_to_file(self, server: Server) -> None:
        """
        Update the msg.info.txt file with new server info (new 4 rows)

        Args:
            server (Server): info about the server
        """
        try:
            # Convert Server object to string format
            server_string = f"{server.server_ip}:{server.server_port}\n{server.server_name}\n{server.server_id}\n{server.symmetric_key}\n"
            server_string = f"{server.server_ip}:{server.server_port}\n{server.server_name}\n{server.server_id}\n{server.symmetric_key}\n"
            
            # Update the text file with the server details
            update_txt_file(self.msg_file, server_string)
        except Exception as e:
            print(f"Failed to add server to txt file: '{self.msg_file}', with the next server details: '{server}'")
            raise

    def __read_server_file(self) -> list[Server]:
        """
        Private function to read servers file (msg.info.txt) and return list of Servers from file

        Returns:
            list[Server]: list of Server objects that were extracted from file
        """
        servers = []
        # Acquire the lock before reading from the file
        with self.server_file_lock:
            with open(self.msg_file, 'r') as file:
                lines = file.readlines()
        # Release the lock as soon as the file reading is done
        # Now we have the data and can process it without holding the lock
        num_lines = len(lines)
        for i in range(0, num_lines, 4):
            ip_port = lines[i].strip().split(':')
            server_ip = ip_port[0]
            server_port = int(ip_port[1])
            server_name = lines[i + 1].strip()
            server_id = lines[i + 2].strip()
            symmetric_key = lines[i + 3].strip()
            servers.append(Server(server_ip, server_port, server_name, server_id, symmetric_key))
        return servers

    def __is_server_exist_by_name(self, server_name: str) -> bool:
        """
        Return True if server_name exists in msg.info.txt

        Args:
            server_name (str): Server's name

        Returns:
            bool: True if exists, False otherwise
        """
        server_list = self.__read_server_file()
        for server in server_list:
            if server.server_name == server_name:
                return True
        return False

    def __is_ip_port_in_use(self, ip: str, port: int) -> bool:
        """
        Check if the given IP address and port are already in use by any server.

        Args:
            ip (str): The IP address to check.
            port (int): The port number to check.

        Returns:
            bool: True if the IP address and port are already in use, False otherwise.
        """
        if not is_valid_port(port):
            raise ValueError(f"The port number '{port}' is not valid. Please provide a valid port number between 0 and 65535.")
        
        # Get the list of servers
        servers = self.__read_server_file()
        
        # Iterate over the servers and check if any of them use the given IP address and port
        for server in servers:
            if server.server_ip == ip and server.server_port == port:
                return True  # IP address and port are in use by this server
        
        return False  # IP address and port are not in use by any server
    
    #Build servers list to send
    def build_servers_list(self, servers: list[Server]) -> bytes:
        """
        Build a byte concatenation of 'ServerInList' objects from given list of 'Server'

        Args:
            servers (list[Server]): Servers to extract the parameters from

        Returns:
            bytes: concatenation of bytes of 'ServerInList' objects
        """
        server_in_list_objects = []
        for server in servers:
            # Convert Server object to ServerInList object
            server_id_bytes = bytes.fromhex(server.server_id)
            server_in_list = ServerInList(server_id_bytes, server.server_name, server.server_ip, server.server_port)
            server_in_list_objects.append(server_in_list)
        
        serialized_data = b''
        for server in server_in_list_objects:
            serialized_data += server.pack()
        return serialized_data


    # ------- GETS -------
    @property
    def version(self):
        return self.__version
    
    @property
    def max_connections(self):
        return self.__server_max_connections
    
    @property
    def port_file(self):
        return self.__port_file_location
    
    @property
    def msg_file(self):
        return self.__msg_file_location
    
    @property
    def clients_file(self):
        return self.__clients_file_location
    
    @property
    def client_file_lock(self):
        return self.__client_file_lock
    
    @property
    def server_file_lock(self):
        return self.__msg_file_lock
    
    @property
    def ticket_expiration_time(self):
        return self.__ticket_expiration_time
    
    # ------- GETS -------
    def set_version(self, version: int) -> None:
        self.__version = version
    
    def set_ticket_expiration_time(self, timedelta_obj: timedelta) -> None:
        self.__ticket_expiration_time = timedelta_obj

    # ------- RUN SERVER ------- 
    def run_auth_server(self):
        """
        Create a TCP/IP socket
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Bind the socket to the port
        port = read_port(self.port_file, self.server_default_port)
        server_address = (self.server_name, port)
        print("starting up on '%s' port '%s'" %server_address)
        sock.bind(server_address)

        sock.listen(self.max_connections)
        
        #load server and clients info
        client_list = self.__read_clients_file() #NOTE: required to load the client's into the RAM from start
        server_list = self.__read_server_file()

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
