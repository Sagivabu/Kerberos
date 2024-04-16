import socket
import threading
import uuid
from datetime import datetime, timedelta
from utils.enums import RequestEnums, ResponseEnums
from utils.utils import read_port, update_txt_file, read_txt_file, datetime_to_bytes
from utils.structs import RequestStructure, ResponseStructure ,Client, Server, EncryptedKey, Ticket, SymmetricKeyResponse
from utils.encryption import encrypt_with_aes_cbc, derive_encryption_key, generate_random_iv, generate_aes_key


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
                version: int = 1):
        self.server_name = server_name 
        self.server_default_port = server_default_port
        self.__server_max_connections = server_connections
        self.__port_file_location = port_file_location
        self.__msg_file_location = msg_file_location
        self.__clients_file_location = clients_file_location
        self.__ticket_expiration_time:timedelta = timedelta(hours=1)
        self.__version = version

        #files locks
        self.__client_file_lock = threading.Lock() # Define a lock to manage the threads that attend to clients.txt file. NOTE: the lock is per instance of the class!
        self.__msg_file_lock = threading.Lock() # Define a lock to manage the threads that attend to msg.info.txt file
       
    def __receive_all(self, connection: socket.socket, size: int):
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

    def __handle_client(self, connection: socket.socket, client_address: tuple[str, int]):
        """
        Function to handle communication with a single client.
        """
        print(f"Connection from {client_address}")

        try:
            # Receive the message
            data = self.__receive_all(connection, 23)  # Assuming header size is fixed at 23 bytes

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
                        response = ResponseStructure(request_obj.version, ResponseEnums.REGISTRATION_FAILED.value, payload=None).pack() #prepare response as bytes
                        connection.sendall(response)
                    else:
                        if not self.__is_client_exist_by_name(client_name): #if client not exists in list
                            try:
                                # Create new 'Client' object
                                new_uuid = str(uuid.uuid4())
                                new_client = Client.from_plain_password(new_uuid, client_name, client_password, datetime.now())
                                
                                #add it to clients.txt file
                                self.add_new_client_to_file(new_client)

                                #send success response
                                response = ResponseStructure(request_obj.version, ResponseEnums.REGISTRATION_SUCCESS.value, new_uuid).pack() #prepare response as bytes
                                connection.sendall(response)
                                
                            except Exception as e:
                                print(f"Failed to register new client with name: '{client_name}', password: '{client_password}'.\n{e}")
                                response = ResponseStructure(request_obj.version, ResponseEnums.REGISTRATION_FAILED.value, None).pack() #prepare response as bytes
                                connection.sendall(response)
                        else:
                            print(f"Failed to register new client, name '{client_name}' already exists in DB.")
                            response = ResponseStructure(request_obj.version, ResponseEnums.REGISTRATION_FAILED.value, None).pack() #prepare response as bytes
                            connection.sendall(response)
                    
                case RequestEnums.SERVER_REGISTRATION: # Server Registration (NOTE: BONUS)
                    pass

                case RequestEnums.SERVER_LIST: # Server List (NOTE: BONUS)
                    pass

                case RequestEnums.SYMMETRY_KEY: # Symmetric key to connect a server
                    print("Received Symmetric key to a server request:")
                    print("Payload:", request_obj.payload)

                    try: #get request's payload
                        server_id, nonce = request_obj.extract_server_id_nonce()
                    except Exception as e: #if 
                        print(f"Failed to extract server_id and nonce from given payload.\t{e}")
                        response = ResponseStructure(request_obj.version, ResponseEnums.SERVER_GENERAL_ERROR.value, payload=None).pack() #prepare response as bytes
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
                            response = ResponseStructure(request_obj.version, ResponseEnums.SERVER_GENERAL_ERROR.value, payload=None).pack() #prepare response as bytes
                            connection.sendall(response)
                        
                        # If Client not found return error (Can happen only in case the client is not registered in DB)
                        elif not the_client:
                            print(f"Failed to find the client information in DB following client_id from request header: '{request_obj.client_id}'. Client may not be registered.")
                            response = ResponseStructure(request_obj.version, ResponseEnums.SERVER_GENERAL_ERROR.value, payload=None).pack() #prepare response as bytes
                            connection.sendall(response)
                        
                        else:
                            # Prepare the response with the server's information
                            AES_key = generate_aes_key() # Generate AES_key for the server-client communication

                            #--1-- Prepare the EncryptedKey object
                            client_key = derive_encryption_key(the_client.password_hash) # Step 1: Derive client key based on the client's password_hash
                            encrypted_key_iv = generate_random_iv() # Step 2: Generate random IV for the encryption of the nonce and AES_key
                            encrypted_nonce = encrypt_with_aes_cbc(client_key, encrypted_key_iv, nonce.encode()) # Step 3: Encrypt the nonce
                            encrypted_aes_key = encrypt_with_aes_cbc(client_key, encrypted_key_iv, AES_key) # Step 4: Encrypt the AES_key
                            encrypted_key = EncryptedKey(encrypted_key_iv=encrypted_key_iv,
                                         encrypted_nonce=encrypted_nonce,
                                         encrypted_server_key=encrypted_aes_key)

                            #--2-- Prepare the Ticket object
                            msg_server_key = derive_encryption_key(the_server.symmetric_key.encode()) # Step 1: Derive msg server key based on the server's symmetric key
                            ticket_iv = generate_random_iv() # Step 2: Generate random IV for the encryption of the Expiration_time and AES_key
                            creation_time = datetime.now() # Step 3: Define creation_time
                            expiration_time = creation_time + self.ticket_expiration_time # Step 4: Create the expiration time based on the creation time and the Auth_server deltas
                            creation_time_8_bytes = datetime_to_bytes(creation_time)
                            expiration_time_8_bytes = datetime_to_bytes(expiration_time)
                            server_encrypted_aes_key = encrypt_with_aes_cbc(msg_server_key, ticket_iv, AES_key) # Step 5: Encrypt the AES key
                            encrypted_expiration_time = encrypt_with_aes_cbc(msg_server_key, ticket_iv, expiration_time_8_bytes) # Step 6: Encrypt the Expiration_time
                            ticket = Ticket(server_version=self.version, #NOTE: XXX: Not sure which version (Auth_server / msg_server)
                                            client_id=the_client.id,
                                            server_id=the_server.server_id,
                                            creation_time = creation_time
                                            ticket_iv= ticket_iv,
                                            aes_key=) #TODO: STOPPED HERE BECAUSE SEGGEV IS YELLING AT ME!
                            #--3-- Prepare the SymmetricKeyResponse object

                    
                case _:
                    print("Unknown request code")
                    # TODO: return response of Unkown request
        finally:
            # Clean up the connection
            connection.close()
     
    # ------- Client handle Functions -------
    def add_new_client_to_file(self, client_obj: Client) -> None:
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
        Private function to read clients file and deliver the object to other functions (find client, remove, update...)

        Returns:
            list[Client]: list of Client objects
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
    
    def __read_server_file(self) -> list[Server]:
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

    def __is_client_exist(self, client_obj: Client) -> bool:
        """
        Return True if client_obj exists in client.txt based on client_name ONLY

        Args:
            client_obj (Client): Client object

        Returns:
            bool: True if exists, False otherwise
        """
        client_list = self.__read_clients_file()
        for client in client_list:
            if client.name == client_obj.name: #NOTE: It was requested in the project to find if only same name exists
                return True
        return False
    
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
