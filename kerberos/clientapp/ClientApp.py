import os
import socket
import struct
import hashlib
from kerberos.utils.utils import build_reg_payload, is_valid_port, generate_nonce
from kerberos.utils.structs import RequestStructure, ResponseStructure, RESPONSE_HEADER_SIZE, SymmetricKeyResponse, Ticket, EncryptedKey
from kerberos.utils.enums import RequestEnums, ResponseEnums
from kerberos.utils import decryption as Dec

class ClientApp:
    def __init__(self) -> None:
        self.name = None
        self.password = None
        self.id = None
        self.servers_dict = {} #key: "ip:port", value: dict  ->  keys: 'id', 'aes_key', 'ticket'
        self.__srv_file = f"{self.name}_srv.info"
        self.__me_file = f"{self.name}_me.info"
        
        self.__salt = f"Sagiv_Abu_206122459_{self.name}".encode() #each client have its own salt for derive client key
        
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

    def __read_info_file(self):
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
        """ Read the servers from srv.info file and create dicionary when key is IP. The dicionary is self parameter. """
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
        elif len(parts) >= 2 and parts[0].lower() == "connect":
            try:
                # Extract IP and port
                ip_port = parts[1].split(":")
                if len(ip_port) != 2:
                    print("Invalid format. Please use 'connect ip:port'.")
                    return
                ip = ip_port[0]
                port = int(ip_port[1])
                if not is_valid_port(port):
                    print(f"The port number '{port}' is not valid. Please provide a valid port number between 0 and 65535.")
                    return

                # Call get_sym_key function
                self.connect_server(ip, port) #TODO
            except Exception as e:
                print(f"Failed to connect to the server '{ip}:{port}'.\t{e}")
        elif len(parts) >= 2 and parts[0].lower() == "set_password":
            # Set new password
            new_password = ' '.join(parts[1:])
            self.set_password(new_password)
        elif len(parts) >= 1 and parts[0].lower() == "get_servers_list":
            # Get servers list
            self.get_servers_list()
        elif len(parts) >= 2 and parts[0].lower() == "add_server":
            # Add server
            ip_port = parts[1].split(":")
            if len(ip_port) != 2:
                print("Invalid format. Please use 'add_server ip:port'.")
                return
            ip = ip_port[0]
            port = int(ip_port[1])
            self.__add_server_info(ip, port)
        elif len(parts) >= 3 and parts[0].lower() == "send":
            # Send message
            ip_port = parts[1].split(":")
            if len(ip_port) != 2:
                print("Invalid format. Please use 'send ip:port msg'.")
                return
            ip = ip_port[0]
            port = int(ip_port[1])
            msg = ' '.join(parts[2:])
            self.send_msg(ip, port, msg) #TODO
        elif len(parts) >= 1 and parts[0].lower() == "register":
            # Register
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
            # Create a socket object
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # get auth_server address
            auth_server_ip, auth_server_port = self.__get_auth_server_info()
            
            # Connect to the auth server
            client_socket.connect((auth_server_ip, auth_server_port))
            
            #create the payload
            nonce = generate_nonce()
            payload = f"{server_id}\x00{nonce.decode('utf-8')}"
            
            # Create the symmetric key Request
            request = RequestStructure(client_id=self.id,
                                       version=1,
                                       code=RequestEnums.SYMMETRIC_KEY.value,
                                       payload=payload).pack()
            
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
                    #get the SymmetricKeyResponse object
                    SymKey_response = SymmetricKeyResponse.unpack(payload.encode('utf-8'))
                    
                    #validate client id
                    if not SymKey_response.client_id == self.id:
                        print(f"Response include incorrect client ID = '{SymKey_response.client_id}' , when my client_id is '{self.id}'")
                        return
                    
                    decrypted_nonce, decrypted_key = Dec.client_decrypt_encrypted_key(
                        encrypted_key_iv=SymKey_response.encrypted_key.encrypted_key_iv,
                        encrypted_nonce=SymKey_response.encrypted_key.encrypted_nonce,
                        encrypted_server_key=SymKey_response.encrypted_key.encrypted_server_key,
                        password=self.password,
                        salt=self.salt
                    )
                    
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
                        self.servers_dict[key]['id'] = server_id
                        self.servers_dict[key]['key'] = decrypted_key
                        self.servers_dict[key]['ticket'] = SymKey_response.ticket
                        
                    print(f"Symmetric key received successfully")
                case ResponseEnums.SERVER_GENERAL_ERROR:
                    print(f"Failed to get Symmetric Key for server '{server_id}'.")
                case ResponseEnums.SERVER_REJECT_REQUEST:
                    print(f"User is not registered in Auth server, hence request rejected.")
                case _:
                    print(f"Unfamiliar response code: '{response_obj.code}'.")

        except Exception as e:
            print(f"Failed to get Symmetric Key for server '{server_id}'.\t{e}")
    
    # get servers list        
    def get_servers_list(self) -> None:
        """ Send Auth_server a request to get list of all servers, and then print it to the user """
        try:
            # Create a socket object
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # get auth_server address
            auth_server_ip, auth_server_port = self.__get_auth_server_info()
            
            # Connect to the auth server
            client_socket.connect((auth_server_ip, auth_server_port))
            
            # Create the servers_list Request
            request = RequestStructure(client_id=self.id,
                                       version=1,
                                       code=RequestEnums.SERVER_LIST.value,
                                       payload=None).pack()
            
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
                    print(f"Server List request complete succefully.\n{response_obj.payload}")
                case ResponseEnums.SERVER_GENERAL_ERROR:
                    print(f"Server List request failed.")
                case ResponseEnums.SERVER_REJECT_REQUEST:
                    print(f"User is not registered in Auth server, hence request rejected.")
                case _:
                    print(f"Unfamiliar response code: '{response_obj.code}'.")

        except Exception as e:
            print(f"Server list request failed, please try again.\t{e}")

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
        # Create a socket object
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            # Connect to the server
            client_socket.connect((auth_server_ip, auth_server_port))
            
            # Create the Registration Request
            reg_payload = build_reg_payload(self.name, self.password)
            request = RequestStructure(client_id="0000000000000000", #NOTE: first ID doesnt matter
                                       version=1, #NOTE: version doesnt matter
                                       code=RequestEnums.CLIENT_REGISTRATION.value,
                                       payload=reg_payload).pack()
            
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