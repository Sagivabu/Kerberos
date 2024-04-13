import socket
import sys
import threading
from datetime import datetime
from utils.enums import RequestEnums
from utils.utils import read_port, update_txt_file, read_txt_file
from utils.structs import RequestStructure, Client

PORT_FILE_PATH = "C:/git/Kerberos/AuthServer/port.info.txt"
MSG_FILE_PATH = "C:/git/Kerberos/AuthServer/msg.info.txt"
CLIENTS_FILE_PATH = "C:/git/Kerberos/AuthServer/clients.txt"

class AuthServer:
    def __init__(self, server_name: str = "localhost", \
                server_default_port: int = 1256, \
                server_connections: int = 10, \
                port_file_location: str = PORT_FILE_PATH, \
                msg_file_location: str = MSG_FILE_PATH, \
                clients_file_location: str = CLIENTS_FILE_PATH):
        self.server_name = server_name 
        self.server_default_port = server_default_port
        self.__server_max_connections = server_connections
        self.__port_file_location = port_file_location
        self.__msg_file_location = msg_file_location
        self.__clients_file_location = clients_file_location

        self.__file_lock = threading.Lock() # Define a lock to manage the threads. NOTE: the lock is per instance of the class!

       
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
            match request_obj.code:
                case RequestEnums.CLIENT_REGISTRATION: # Client Registration
                    print("Received client registration request:")
                    print("Client ID:", request_obj.client_id)
                    print("Version:", request_obj.version)
                    print("Payload:", request_obj.payload)
                    # TODO: Process registration request...
                    
                case RequestEnums.SERVER_REGISTRATION: # Server Registration (NOTE: BONUS)
                    pass

                case RequestEnums.SERVER_LIST: # Server List (NOTE: BONUS)
                    pass

                case RequestEnums.SYMMETRY_KEY: # Symmetric key to connect a server
                    print("Received Symmetric key to a server request:")
                    print("Client ID:", request_obj.client_id)
                    print("Version:", request_obj.version)
                    print("Payload:", request_obj.payload)
                    # TODO: Process connection request...
                case _:
                    print("Unknown request code")
                    # TODO: return response of Unkown request
        finally:
            # Clean up the connection
            connection.close()
     
    # ------- Functions -------
    def update_clients_file(self, client_obj: Client) -> None:
        """
        Update the clients.txt file

        Args:
            client_obj (Client): info about client
        """
        with self.file_lock:
            update_txt_file(self.clients_file, client_obj.print_as_row() + "\n")

    def __read_clients_file(self) -> list[Client]:
        """
        Private function to read clients file and deliver the object to other functions (find client, remove, update...)

        Returns:
            list[Client]: list of Client objects
        """
        with self.file_lock: #read file with lock premit
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
    
    #TODO: def is_client_exist(client_obj: Client) -> bool: #STOPPED HERE!



    # ------- GETS -------
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
    def file_lock(self):
        return self.__file_lock
    



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
