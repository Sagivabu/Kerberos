import os
import socket
import struct
import hashlib
from datetime import datetime
from kerberos.utils.utils import build_reg_payload, is_valid_port, generate_nonce, is_valid_ip, datetime_to_bytes
from kerberos.utils.structs import RequestStructure, ResponseStructure, RESPONSE_HEADER_SIZE, SymmetricKeyResponse, EncryptedKey, Authenticator, ServerInList, EncryptedMessage
from kerberos.utils.enums import RequestEnums, ResponseEnums
from kerberos.utils import decryption as Dec
from kerberos.utils import encryption as Enc

class ClientApp:
    def __init__(self, version: int = 24) -> None:
        self.name = None
        self.password = None
        self.id = None
        self.servers_dict = {} #key: "ip:port", value: dict  ->  keys: 'id', 'aes_key', 'ticket'
        self.__srv_file = f"{self.name}_srv.info"
        self.__me_file = f"{self.name}_me.info"
        
        self.__salt = f"Sagiv_Abu_206122459_{self.name}".encode() #each client have its own salt for derive client key
        self.__version = version
        
        self.startup() #XXX: NOTE: shall i put the startup here?
    
    # ---- Gets ----
    @property
    def srv_file(self):
        return self.__srv_file
    
    @property
    def me_file(self):
        return self.__me_file
    
    @property
    def salt(self):
        return self.__salt
    
    @property
    def version(self):
        return self.__version
    
    # ---- Functions ----
    
    def __receive_all(self, connection: socket.socket, header_size: int) ->bytes:
        """
        Helper function to receive all data from a socket connection matching the format of 'ResponseStructure'.

        Args:
            connection (socket.socket): opened connection
            header_size (int): header size

        Returns:
            bytes: the complete data from the connection
        """
        data = b''
        while len(data) < header_size:
            chunk = connection.recv(header_size - len(data))
            if not chunk:
                raise RuntimeError("Incomplete header data received.")
            data += chunk
        
        # Parse header to determine payload size
        version, code, payload_size = struct.unpack('<1s2sI', data)
        payload_size = int(payload_size)
        
        # Receive the payload
        data += self.__receive_all(connection, payload_size)

        return data

    def __get_auth_server_info(self)-> tuple[str,int]:
        """
        Auth server information appears in the first line of every srv.info file

        Raises:
            e: file not found
            e: invalid data format of ip:port

        Returns:
            tuple (str,int): _description_
        """
        try:
            with open(self.srv_file, "r") as file:
                # Read the first line from the file
                first_line = file.readline().strip()
                # Split the line into IP address and port
                ip, port = first_line.split(":")
                # Convert port to an integer
                port = int(port)
                if not is_valid_port(port):
                    raise Exception(f"The port number '{port}' is not valid. Please provide a valid port number between 0 and 65535.")
                # Return the IP address and port as a tuple
                return ip, port
        except FileNotFoundError:
            print(f"Error: File '{self.srv_file}' not found.")
            return None, None
        except ValueError:
            print(f"Error: Invalid data format in '{self.srv_file}'. Expected 'ip:port'.")
            return None, None
        except Exception as e:
            print(e)
            return None, None
        
    def __create_info_file(self) -> None:
        """ Create '{self.name}_me.info' file with name and id """
        with open(self.me_file, "w") as file:
            file.write(f"{self.name}\n")
            file.write(f"{self.id}\n")

    def __read_info_file(self) -> None:
        """ Read me.info file and overwrite name and id with it """
        if os.path.exists(self.me_file):
            with open(self.me_file, "r") as file:
                lines = file.readlines()
                self.name = lines[0].strip()
                self.id = lines[1].strip()
                
    def __is_user_exists(self) -> bool:
        """
        Check if me.info file exists

        Returns:
            bool: True if exists otherwise False
        """
        if os.path.exists(self.me_file):
            return True
        else: return False
        
    def set_password(self, new_password: str) -> None:
        """ Set new_password

        Args:
            new_password (str): new password
        """
        try:
            # Function to set a new password
            self.password = new_password
            print("Password updated successfully.")
        except Exception as e:
            print(f"Failed to set new password '{new_password}'")
        
    def read_servers_info(self) -> None:
        """ Read the servers from srv.info file and update dicionary where key is IP:PORT. The dicionary is self parameter. """
        try:
            if os.path.exists(self.srv_file):
                with open(self.srv_file, "r") as file:
                    lines = file.readlines()
                    for line in lines:
                        ip, port = line.strip().split(':')
                        if not is_valid_port(int(port)):
                            print(f"Found invalid server address: '{ip}:{port}', port is not valid (must be between 0 ~ 65535).")
                            continue
                        key = f"{ip}:{port}"
                        if key not in self.servers_dict:
                            self.servers_dict[key] = {}
            return self.servers_dict
        except Exception as e:
            print(f"Failed to read '{self.name}_srv.info' file and create dictionary from the servers in it.\t{e}")
            raise e

    def __add_server_info(self, ip: str, port: int) -> None:
        """
        Add server's info to srv.info file and to the dictionary

        Args:
            ip (str): server's ip
            port (int): server's port
        """
        try:
            if not is_valid_port(port):
                raise ValueError(f"The port number '{port}' is not valid. Please provide a valid port number between 0 and 65535.")
            
            if not is_valid_ip(ip):
                print(f"Invalid IP address format")
            
            #check if already exists
            key = f"{ip}:{port}"
            self.read_servers_info()
            if key in self.servers_dict:
                print(f"Failed to add server '{ip}:{port}' because it already exists in DB")
                return            
            
            #update file
            if not os.path.exists(self.srv_file): #create it if not exists
                with open(self.srv_file, "w") as file:
                    file.write(f"{ip}:{port}\n")
            else:
                with open(self.srv_file, "a") as file:
                    file.write(f"{ip}:{port}\n")
                    
            #update dict
            self.servers_dict[key] = {}
        except Exception as e:
            print(f"Failed to add server '{ip}:{port}' to '{self.name}_srv.info' file and to dictionary.\t{e}")
            return
        

    # --------- handle function + sub_functions ---------
    def handle_user_input(self, user_input: str) -> None:
        """ Get user requests from cmd and activate relevant functions

        Args:
            user_input (str): user input from cmd/cli
        """
        # Function to handle user input
        parts = user_input.split()
        
        # ---- GET AES KEY FOR SERVER ----
        if len(parts) >= 3 and parts[0].lower() == "get_key":
            try:
                ip_port = parts[1].split(":")
                if len(ip_port) != 2:
                    print("Invalid format. Please use 'get_key ip:port server_id'.")
                    return
                ip = ip_port[0]
                port = int(ip_port[1])
                if not is_valid_port(port):
                    print(f"The port number '{port}' is not valid. Please provide a valid port number between 0 and 65535.")
                    return
                server_id = parts[2]
                self.get_sym_key(ip, port, server_id)
            except ValueError:
                print("Invalid port number.")
                
        # ---- CONNECT MSG SERVER ----
        elif len(parts) >= 2 and parts[0].lower() == "connect":
            try:
                # Extract IP and port
                ip_port = parts[1].split(":")
                if len(ip_port) != 2:
                    print("Invalid format. Please use 'connect ip:port'.")
                    return
                #validate ip
                ip = ip_port[0]
                if not is_valid_ip(ip):
                    print(f"Invalid IP address format")
                    return
                #validate port
                port = int(ip_port[1])
                if not is_valid_port(port):
                    print(f"The port number '{port}' is not valid. Please provide a valid port number between 0 and 65535.")
                    return
                self.connect_server(ip, port)
            except Exception as e:
                print(f"Failed to connect to the server '{ip}:{port}'.\t{e}")
                
        # ---- SET PASSWORD ----
        elif len(parts) >= 2 and parts[0].lower() == "set_password":
            new_password = ' '.join(parts[1:])
            self.set_password(new_password)
            
        # ---- GET SERVERS LIST ----
        elif len(parts) >= 1 and parts[0].lower() == "get_servers_list":
            self.get_servers_list()
            
        # ---- ADD SERVER ----
        elif len(parts) >= 2 and parts[0].lower() == "add_server":
            ip_port = parts[1].split(":")
            if len(ip_port) != 2:
                print("Invalid format. Please use 'add_server ip:port'.")
                return
            ip = ip_port[0]
            port = int(ip_port[1])
            self.__add_server_info(ip, port)
            
        # ---- SEND MESSAGE ----
        elif len(parts) >= 3 and parts[0].lower() == "send":
            #extract ip&port
            ip_port = parts[1].split(":")
            if len(ip_port) != 2:
                print("Invalid format. Please use 'send ip:port msg'.")
                return
            
            #validate ip
            ip = ip_port[0]
            if not is_valid_ip(ip):
                print(f"Invalid IP address format")
                return
            #validate port
            port = int(ip_port[1])
            if not is_valid_port(port):
                print(f"The port number '{port}' is not valid. Please provide a valid port number between 0 and 65535.")
                return
            
            #extract message
            msg = ' '.join(parts[2:])
            self.send_msg(ip, port, msg)
            
        # ---- REGISTER ---- 
        elif len(parts) >= 1 and parts[0].lower() == "register":
            self.startup()
        else:
            print("Invalid command. Please use 'connect ip:port', 'set_password password', 'get_servers_list', 'add_server ip:port', 'send ip:port msg', or 'register'.")

    # symmetric key request
    def get_sym_key(self, ip: str, port: int, server_id: str) -> None:
        """ This function send Auth server a request for symmetric_key for specific server [by Server_ID] and save the result in the server's item in self.servers_dict.
        It is also deliver the symmetric key to the target server to establish future connection

        Args:
            server_id (str): target server's id
        """
        try:
            # get auth_server address
            auth_server_ip, auth_server_port = self.__get_auth_server_info()

            #create the payload
            nonce = generate_nonce()
            payload = f"{server_id}\x00{nonce.decode('utf-8')}"
            
            # Create the symmetric key Request
            request = RequestStructure(client_id=self.id,
                                       version=self.version,
                                       code=RequestEnums.SYMMETRIC_KEY.value,
                                       payload=payload).pack()
            
            # Create a socket object
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        
            # Connect to the auth server
            client_socket.connect((auth_server_ip, auth_server_port))
            
            # Send data to the server
            client_socket.sendall(request)

            # Receive response from the server
            response_data = self.__receive_all(client_socket, header_size=RESPONSE_HEADER_SIZE)  # Assuming 'ResponseStructure' header size is fixed at 7 bytes
            
            # Close the socket
            client_socket.close()
            
            # Unpack the received data into a ResponseStructure object
            response_obj = ResponseStructure.unpack(response_data)
            
            # Process the message based on the code
            responseEnum_obj = ResponseEnums.find(response_obj.code)
            match responseEnum_obj:
                case ResponseEnums.SYMMETRIC_KEY:
                    #Unpack the Payload
                    SymKey_response = SymmetricKeyResponse.unpack(response_obj.payload.encode('utf-8'))
                    
                    #validate client id
                    if not SymKey_response.client_id == self.id:
                        print(f"Response include incorrect client ID = '{SymKey_response.client_id}' , when my client_id is '{self.id}'")
                        return
                    
                    #decrypt EncryptedKey parameters
                    password_hash = hashlib.sha256(self.password.encode()).digest() # Create password_hash
                    client_key = Dec.derive_client_key(password_hash, self.salt) # Derive client key from password hash
                    encrypted_key = EncryptedKey.unpack(SymKey_response.encrypted_key, key=client_key)
                    decrypted_nonce = encrypted_key.nonce
                    decrypted_key = encrypted_key.aes_key
                    
                    # !!! Check if decrypted succeed !!!
                    if nonce != decrypted_nonce:
                        print(f"Failed to get Symmetric key to target server. origin 'nonce' != 'decrypted_nonce'.\n \
                            This may happen due to incorrect password which lead to incorrect decryption process or incorrect response (imply on a third person reponse)")
                        return
                    else: # The decryption is correct
                        # Save server's information
                        key = f"{ip}:{port}"
                        if key not in self.servers_dict:
                             self.servers_dict[key] = {}
                        self.servers_dict[key]['id'] = server_id # (str)
                        self.servers_dict[key]['key'] = decrypted_key #symmetric key shard with the server (32 bytes)
                        self.servers_dict[key]['ticket'] = SymKey_response.ticket #Ticket encrypted (bytes)
                        
                    print(f"Symmetric key received successfully")
                case ResponseEnums.SERVER_GENERAL_ERROR:
                    print(f"Failed to get Symmetric Key for server '{server_id}'.")
                case ResponseEnums.SERVER_REJECT_REQUEST:
                    print(f"User is not registered in Auth server, hence request rejected.")
                case _:
                    print(f"Unfamiliar response code: '{response_obj.code}'.")

        except Exception as e:
            print(f"Failed to get Symmetric Key for server '{server_id}'.\t{e}")
    
    # send Authenticator & Ticket to server
    def connect_server(self, ip: str, port: int) -> None:
        try:
            # Get target server info
            key = f"{ip}:{port}"
            target_server = self.servers_dict.get(key)
            if target_server is None or not target_server:
                print(f"Server {key} is not exists in Client's DB, please use 'get_key' command before")
                return

            # Create IV for encryption
            authenticator_iv = Enc.generate_random_iv()
            
            # Create the Authenticator
            authenticator_creation_time = datetime_to_bytes(datetime.now())
            authenticator = Authenticator(
                iv=authenticator_iv,
                version=self.version,
                client_id=self.id.encode(),
                server_id=target_server.get('id').encode(),
                creation_time=authenticator_creation_time
            )
            
            #ecnrypt it
            encrypted_auth = Enc.encrypt_authenticator(authenticator=authenticator, client_key=target_server.get('key'))
            
            #prepare the request
            authenticator_length = len(encrypted_auth).to_bytes(4, byteorder='little')
            ticket = target_server.get('ticket')
            payload = authenticator_length + encrypted_auth + ticket
            request = RequestStructure(client_id=self.id,
                                       version=self.version,
                                       code=RequestEnums.DELIVER_SYMMETRY_KEY.value,
                                       payload=payload).pack()

            # Create a socket object
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Connect to target server
            client_socket.connect((ip, port))
            
            # Send data to the server
            client_socket.sendall(request)

            # Receive response from the server
            response_data = self.__receive_all(client_socket, header_size=RESPONSE_HEADER_SIZE)  # Assuming 'ResponseStructure' header size is fixed at 7 bytes
            
            # Close the socket
            client_socket.close()
            
            # Unpack the received data into a ResponseStructure object
            response_obj = ResponseStructure.unpack(response_data)
            
            # Process the message based on the code
            responseEnum_obj = ResponseEnums.find(response_obj.code)
            match responseEnum_obj:
                case ResponseEnums.SERVER_MESSAGE_ACCEPT_SYMMETRIC_KEY:
                    print(f"Server '{key}' received Symmetric key successfully") #TODO: something to do here?
                case ResponseEnums.SERVER_GENERAL_ERROR:
                    print(f"Server '{key}' failed to receive Symmetric Key.")
                case _:
                    print(f"Unfamiliar response code: '{response_obj.code}'.")

        except Exception as e:
            print(f"Failed to connect the server '{key}'.\t{e}")
        
    # Send message
    def send_msg(self, ip: str, port: int, msg: str):
        try:
            # Get target server info
            key = f"{ip}:{port}"
            target_server = self.servers_dict.get(key)
            if target_server is None or not target_server:
                print(f"Server {key} is not exists in Client's DB, please use 'get_key' command before")
                return

            # Create IV for encryption
            message_iv = Enc.generate_random_iv()
            
            # Create the payload (the EncryptedMessage)
            payload = EncryptedMessage(message_iv, msg).pack(aes_key=target_server.get('key'))
            
            #prepare the request
            request = RequestStructure(client_id=self.id,
                                       version=self.version,
                                       code=RequestEnums.MESSAGE_TO_SERVER.value,
                                       payload=payload).pack()

            # Create a socket object
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Connect to target server
            client_socket.connect((ip, port))
            
            # Send data to the server
            client_socket.sendall(request)

            # Receive response from the server
            response_data = self.__receive_all(client_socket, header_size=RESPONSE_HEADER_SIZE)  # Assuming 'ResponseStructure' header size is fixed at 7 bytes
            
            # Close the socket
            client_socket.close()
            
            # Unpack the received data into a ResponseStructure object
            response_obj = ResponseStructure.unpack(response_data)
            
            # Process the message based on the code
            responseEnum_obj = ResponseEnums.find(response_obj.code)
            match responseEnum_obj:
                case ResponseEnums.SERVER_MESSAGE_RECIEVED_MSG_SUCCESSFULLY:
                    print(f"Server '{key}' received the message successfully")
                case ResponseEnums.SERVER_GENERAL_ERROR:
                    print(f"Server '{key}' failed to receive the message.")
                case _:
                    print(f"Unfamiliar response code: '{response_obj.code}'.")

        except Exception as e:
            print(f"Failed to connect the server '{key}'.\t{e}")
    
    # get servers list
    def get_servers_list(self) -> None:
        """ Send Auth_server a request to get list of all servers, and then print it to the user """
        try:
            # get auth_server address
            auth_server_ip, auth_server_port = self.__get_auth_server_info()
            
            # Create the servers_list Request
            request = RequestStructure(client_id=self.id,
                                       version=self.version,
                                       code=RequestEnums.SERVER_LIST.value,
                                       payload=None).pack()
            
            # Create a socket object
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Connect to the auth server
            client_socket.connect((auth_server_ip, auth_server_port))
            
            # Send data to the server
            client_socket.sendall(request)

            # Receive response from the server
            response_data = self.__receive_all(client_socket, header_size=RESPONSE_HEADER_SIZE)  # Assuming 'ResponseStructure' header size is fixed at 7 bytes
            
            # Close the socket
            client_socket.close()
            
            # Unpack the received data into a ResponseStructure object
            response_obj = ResponseStructure.unpack(response_data)
            
            # Process the message based on the code
            responseEnum_obj = ResponseEnums.find(response_obj.code)
            match responseEnum_obj:
                case ResponseEnums.SERVER_LIST:
                    string_of_print = self.__deserialize_and_print_servers_list(response_obj.payload.encode())
                    print(f"Server List request complete succefully.\n{string_of_print}")
                case ResponseEnums.SERVER_GENERAL_ERROR:
                    print(f"Server List request failed.")
                case ResponseEnums.SERVER_REJECT_REQUEST:
                    print(f"User is not registered in Auth server, hence request rejected.")
                case _:
                    print(f"Unfamiliar response code: '{response_obj.code}'.")

        except Exception as e:
            print(f"Server list request failed, please try again.\t{e}")

    def __deserialize_and_print_servers_list(data: bytes) -> str:
        """
        Return String of ready to print servers list to display to client.

        Args:
            data (bytes): concatenation of bytes which represent list of 'ServerInList' objects

        Returns:
            str: string to print of all server searated on in each row
        """
        # Create list[ServerInList]
        server_list = []
        while data:
            server = ServerInList.unpack(data[:279])  # 16 + 1 + 255 + 4 + 2 = 278
            server_list.append(server)
            data = data[279:]
        
        # Print the list
        result = ""
        for server in server_list:
            result += str(server) + "\n"
        return result

    # Registration process
    def registration_request(self, auth_server_ip: str, auth_server_port: int) -> bool:
        """
        Register to Auth Server, passing the 'name' and 'password' and receiving 'id' from it to update me.info file

        Args:
            auth_server_ip (str): Auth server ip
            auth_server_port (int): Auth server port

        Returns:
            bool: True if process complete successfully, otherwise False
        """
        try:
            # Create the Registration Request
            reg_payload = build_reg_payload(self.name, self.password)
            request = RequestStructure(client_id="0000000000000000", #NOTE: first ID doesnt matter
                                       version=self.version,
                                       code=RequestEnums.CLIENT_REGISTRATION.value,
                                       payload=reg_payload).pack()
            
            # Create a socket object
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Connect to the server
            client_socket.connect((auth_server_ip, auth_server_port))

            # Send data to the server
            client_socket.sendall(request)

            # Receive response from the server
            response_data = self.__receive_all(client_socket, header_size=RESPONSE_HEADER_SIZE)  # Assuming 'ResponseStructure' header size is fixed at 7 bytes
            
            # Close the socket
            client_socket.close()
            
            # Unpack the received data into a ResponseStructure object
            response_obj = ResponseStructure.unpack(response_data)
            
            # Process the message based on the code
            responseEnum_obj = ResponseEnums.find(response_obj.code)
            match responseEnum_obj:
                case ResponseEnums.REGISTRATION_SUCCESS:
                    self.id = response_obj.payload
                    print(f"Registration Process complete succefully")
                    return True
                case ResponseEnums.REGISTRATION_FAILED:
                    print(f"Registration Process Failed")
                    return False
                case ResponseEnums.REGISTRATION_USER_EXISTS:
                    print(f"Failed to register new client, name '{self.name}' already exists in DB.")
                    return False
                case _:
                    print(f"Unfamiliar response code: '{response_obj.code}'")
                    return False

        except Exception as e:
            print(f"Registration Process failed, please try again.\t{e}")

    # Registration & startup process
    def startup(self) -> None:
        """ Get 'username' and 'password' from user, and register to auth_server if needed """
        # Startup server logic
        try:
            # get name and password
            self.name = input("Enter username: ")
            self.password = input("Enter password: ")
            
            if not self.__is_user_exists():           
                # Get Auth Server information
                auth_server_ip, auth_server_port = self.__get_auth_server_info()
                
                if self.registration_request(auth_server_ip, auth_server_port): #Registration process succeed
                    self.__create_info_file()
                    print("Client registration finished successfully!")
                else:
                    self.startup() #repeat the process
                
            else:
                self.__read_info_file()
                
            #read srv.file to update servers dict
            self.read_servers_info()
                
            # end message
            print("Client is ready!")
            print(f"Name: {self.name}, ID: {self.id}")
        except Exception as e:
            print(f"Something went wrong with the startup process of client app.\t{e}")