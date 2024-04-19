import os
import uuid
import socket
import struct
from kerberos.utils.utils import build_reg_payload
from kerberos.utils.structs import RequestStructure, ResponseStructure
from kerberos.utils.enums import RequestEnums, ResponseEnums

class ClientApp:
    def __init__(self) -> None:
        self.name = None
        self.password = None
        self.id = None
        self.servers_dict = {} #key: ip, value: dict  ->  keys: 'port', 'aes_key', 'ticket'
        self.__srv_file = f"{self.name}_srv.info"
        self.__me_file = f"{self.name}_me.info"
    
    # ---- Gets ----
    @property
    def srv_file(self):
        return self.__srv_file
    
    @property
    def me_file(self):
        return self.__me_file
    
    # ---- Functions ----
    
    def __receive_all(self, connection: socket.socket, header_size: int):
        """ Helper function to receive all data from a socket connection matching the format of 'ResponseStructure'. """
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

    def registration_request(self, name: str, password: str) -> None:
        
        # Get Auth Server information
        auth_server_ip, auth_server_port = self.__get_auth_server_info()

        # Create a socket object
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            # Connect to the server
            client_socket.connect((auth_server_ip, auth_server_port))
            
            # Create the Registration Request
            reg_payload = build_reg_payload(name, password)
            request = RequestStructure(client_id="0000000000000000", #NOTE: first ID doesnt matter
                                       version=1, #NOTE: version doesnt matter
                                       code=RequestEnums.CLIENT_REGISTRATION.value,
                                       payload=reg_payload).pack()
            
            # Send data to the server
            client_socket.sendall(request)

            # Receive response from the server
            response_data = self.__receive_all(client_socket, header_size=7)  # Assuming 'ResponseStructure' header size is fixed at 7 bytes
            
            # Unpack the received data into a ResponseStructure object
            response_obj = ResponseStructure.unpack(response_data)
            
            # Process the message based on the code
            responseEnum_obj = ResponseEnums.find(response_obj.code)
            match responseEnum_obj:
                #TODO: STOPPED HERE ~ Need to address to any possible response

        finally:
            # Close the socket
            client_socket.close()

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
                # Return the IP address and port as a tuple
                return ip, port
        except FileNotFoundError:
            print(f"Error: File '{self.srv_file}' not found.")
            return None, None
        except ValueError:
            print(f"Error: Invalid data format in '{self.srv_file}'. Expected 'ip:port'.")
            return None, None

    def __create_info_file(self, id: str):
        with open(self.me_file, "w") as file:
            file.write(f"{self.name}\n")
            file.write(f"{id}\n")
        self.id = id

    def __read_info_file(self):
        if os.path.exists(self.me_file):
            with open(self.me_file, "r") as file:
                lines = file.readlines()
                self.name = lines[0].strip()
                self.id = lines[1].strip()
                
    def __is_user_exists(self) -> bool:
        if os.path.exists(self.me_file):
            return True
        else: return False
        

    def startup(self):
        #read srv.file
            self.read_servers_info()
        # Startup server logic
        self.name = input("Enter username: ")
        self.password = input("Enter password: ")
        
        if not self.__is_user_exists():
            self.registration_request(self.name, self.password)
            self.__create_info_file(str(uuid.uuid4()))
            
        else:
            self.__read_info_file()
            
        # Your TCP server startup logic goes here
        print("Server started successfully!")
        print(f"Name: {self.name}, ID: {self.id}")
        
        
    def read_servers_info(self) -> None:
        """ Read the servers from srv.info file and create dicionary when key is IP. The dicionary is self parameter. """
        try:
            self.servers_dict = {}
            if os.path.exists(self.srv_file):
                with open(self.srv_file, "r") as file:
                    lines = file.readlines()
                    for line in lines:
                        ip, port = line.strip().split(':')
                        self.servers_dict[ip] = {'port': int(port)}
            return self.servers_dict
        except Exception as e:
            print(f"Failed to read '{self.name}_srv.info' file and create dictionary from the servers in it.\t{e}")
            raise e

    def add_server_info(self, ip: str, port: int) -> None:
        """
        Add server's info to srv.info file and to the dictionary

        Args:
            ip (str): server's ip
            port (int): server's port
        """
        try:
            #update file
            if not os.path.exists(self.srv_file): #create it if not exists
                with open(self.srv_file, "w") as file:
                    file.write(f"{ip}:{port}\n")
            else:
                with open(self.srv_file, "a") as file:
                    file.write(f"{ip}:{port}\n")
        except Exception as e:
            print(f"Failed to add server '{ip}:{port}' to '{self.name}_srv.info' file and to dictionary.\t{e}")
            raise e
        
        #update dict
        self.servers_dict[ip] = {'port': int(port)}


        
    