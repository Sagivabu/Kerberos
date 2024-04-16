import struct
import datetime
import hashlib
from typing import Optional, List
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from datetime import datetime, timezone

class ResponseStructure:
    def __init__(self, version: str, code: str, payload: Optional[str]) -> None:
        self.version = version[:1]  # Limit to 1 byte
        self.code = code[:2]  # Limit to 2 bytes
        self.payload_size = len(payload.encode('utf-8')) if payload else 0 # len() return int (= 4 bytes)
        self.payload = payload
        
    # ---------- PACK / UNPACK ----------
    def pack(self) -> bytes:
        ''' object method to pack the object'''
        version_bytes = self.version.encode('utf-8')
        code_bytes = self.code.encode('utf-8')

        if self.payload is not None:
            payload_bytes = self.payload.encode('utf-8')
        else:
            payload_bytes = b''

        format_string = f'<1s2sI{len(payload_bytes)}s'
        return struct.pack(format_string, version_bytes, code_bytes, self.payload_size, payload_bytes)
    
    @classmethod
    def unpack(cls, data: bytes) -> 'ResponseStructure':
        ''' class method to unpack data and creating new object \n
            'data' - bytes object (=usually ResponseStructure object that is after 'pack' method)\n
            return - new ResponseStructure object'''
        format_string = '<1s2sI'
        size_of_header = struct.calcsize(format_string)
        header = struct.unpack(format_string, data[:size_of_header])
        payload = data[size_of_header:]
        return cls(header[0].decode('utf-8'), header[1].decode('utf-8'), payload.decode('utf-8'))
    
    # ---------- functions related to Specific Codes ----------
    def extract_client_id(self) -> str: # Code 1600 (Registration SUCCESS)
        # Validate that the payload contains exactly 16 characters
        if len(self.payload) != 16:
            raise ValueError("Payload must contain exactly 16 characters")

        return self.payload
        
class RequestStructure:
    def __init__(self, client_id: str, version: str, code: str, payload: Optional[str]) -> None:
        self.client_id = client_id[:16]  # Limit to 16 bytes
        self.version = version[:1]  # Limit to 1 byte
        self.code = code[:2]  # Limit to 2 bytes
        self.payload_size = len(payload.encode('utf-8')) if payload else 0 # len() return int (= 4 bytes)
        self.payload = payload
        
    
    # ---------- PACK / UNPACK ----------
    def pack(self) -> bytes:
        ''' object method to pack the object'''
        client_id_bytes = self.client_id.encode('utf-8')
        version_bytes = self.version.encode('utf-8')
        code_bytes = self.code.encode('utf-8')

        if self.payload is not None:
            payload_bytes = self.payload.encode('utf-8')
        else:
            payload_bytes = b''

        format_string = f'<16s1s2sI{len(payload_bytes)}s'
        return struct.pack(format_string, client_id_bytes, version_bytes, code_bytes, self.payload_size, payload_bytes)
    
    @classmethod
    def unpack(cls, data: bytes) -> 'RequestStructure':
        ''' class method to unpack data and creating new object \n
            'data' - bytes object (=usually RequestStructure object that is after 'pack' method)\n
            return - new RequestStructure object'''
        format_string = '<16s1s2sI'
        size_of_header = struct.calcsize(format_string)
        header = struct.unpack(format_string, data[:size_of_header])
        payload = data[size_of_header:]
        return cls(header[0].decode('utf-8'), header[1].decode('utf-8'), header[2].decode('utf-8'), payload.decode('utf-8'))
    
    
    # ---------- functions related to Specific Codes ----------
    def extract_name_password(self) -> tuple[str, str]: # Code 1024 (Registration)
        """
        Validate it is "Registration" request and extract name and password from payload

        Returns:
            tuple[str, str]: return (name, password) as tuple
        """
        # Find the index of the first null terminator in the payload
        null_index = self.payload.find('\x00')
        if null_index == -1:
            raise ValueError("Payload does not contain null terminator")

        # Extract the name and password from the payload
        parts = self.payload.split('\x00') #separate by null terminated character
        if len(parts) != 2: #VALIDATION: only 2 strings should exists
            raise ValueError("Payload does not contain exactly two strings")

        name = parts[0].strip()
        password = parts[1].strip()
        return name, password
    
    def extract_server_id_nonce(self) -> tuple[bytes, bytes]: # Code 1027 (Symmetric key for a server)
        """
        Validate it is "Symmetric key for a server" request and extract server_id and nounce from payload

        Returns:
            tuple[bytes, bytes]: return (server_id, nounce) as tuple of bytes
        """
        # Find the index of the first null terminator in the payload
        null_index = self.payload.find('\x00')
        if null_index == -1:
            raise ValueError("Payload does not contain null terminator")

        # Extract the server ID and nonce from the payload
        parts = self.payload.split('\x00')
        if len(parts) != 2:
            raise ValueError("Payload does not contain exactly two parameters")

        server_id = parts[0].encode('utf-8')
        nonce = parts[1].encode('utf-8')

        # Validate the lengths of the extracted parameters
        if len(server_id) != 16:
            raise ValueError("Server ID must be exactly 16 bytes")
        if len(nonce) != 8:
            raise ValueError("Nonce must be exactly 8 bytes")

        return server_id, nonce
    
class Client:
    def __init__(self, id: str, name: str, password_hash: bytes, datetime_obj: datetime.datetime) -> None:
        """
        Create Client's object

        Args:
            id (str): 16 bytes of id 
            name (str): 255 characters of name
            password_hash (bytes): SHA-256 password hash (32 bytes)
            datetime_obj (datetime.datetime): datetime object including: year, month, day, hour, minute, second
        """
        # Convert user_id string to bytes (UTF-8 encoding)
        self.id = id.encode('utf-8')[:16]  # Limit to 16 bytes
        self.name = name[:255]  # Limit to 255 characters
        self.password_hash = password_hash  # Should be exactly 32 bytes
        self.lastseen = Lastseen.from_datetime(datetime_obj)

    @classmethod
    def from_plain_password(cls, id: str, name: str, password: str, datetime_obj: datetime.datetime):
        """
        Create Client's object from plain password (before hashing)

        Args:
        id (str): 16 bytes of id 
        name (str): 255 characters of name
        password (bytes): string
        datetime_obj (datetime.datetime): datetime object including: year, month, day, hour, minute, second

        Returns:
            Client: return 'Client''s object
        """
        password_hash = hashlib.sha256(password.encode()).digest()
        return cls(id, name, password_hash, datetime_obj)

    def print_as_row(self):
        """
        Return string of Client's info to write into a file
        
        Returns:
            string: in the next format -  "ID: Name: PasswordHash: LastSeen"
        """
        return f"{self.id}: {self.name}: {self.password_hash}: {self.lastseen.print_datetime()}"
    
    @staticmethod
    def find_client(client_list: List['Client'], client_id: str) -> Optional['Client']:
        """
        Find the client object with the given ID in the list of client objects.

        Args:
            client_list (List[Client]): List of Client objects
            client_id (str): ID of the client to find

        Returns:
            Optional[Client]: The client object if found, None otherwise
        """
        client_id_bytes = client_id.encode('utf-8')[:16]  # Limit to 16 bytes
        for client in client_list:
            if client.id == client_id_bytes:
                return client
        return None

    #compare to other Client object
    def __eq__(self, other):
        """
        Override the equality comparison for Client objects.

        Args:
            other (Client): Another Client object to compare with.

        Returns:
            bool: True if the two Client objects are equal, False otherwise.
        """
        if isinstance(other, Client):
            return (
                self.id == other.id and
                self.name == other.name and
                self.password_hash == other.password_hash and
                self.lastseen == other.lastseen
            )
        return False

class Server:
    def __init__(self, server_ip: str, server_port: int, server_name: str, server_id: str, symmetric_key: str):
        """
        Create a Server object.

        Args:
            server_ip (str): The server's IP address.
            server_port (int): The server's port number.
            server_name (str): The server's name.
            server_id (str): The server's unique ID in ASCII where every 2 chars represent 8 bits in hex.
            symmetric_key (str): The long-term symmetric key for the server in Base64 format.
        """
        self.server_ip = server_ip
        self.server_port = server_port
        self.server_name = server_name[:255]  # Limit to 255 characters
        self.server_id = server_id
        self.symmetric_key = symmetric_key

    def write_to_txt(self, file_path: str):
        """
        Write the server details to a text file in the specified format.

        Args:
            file_path (str): The path to the text file.
        """
        with open(file_path, 'w') as file:
            file.write(f"{self.server_ip}:{self.server_port}\n")
            file.write(f"{self.server_name}\n")
            file.write(f"{self.server_id}\n")
            file.write(f"{self.symmetric_key}\n")
    
    @staticmethod
    def find_server(server_list: List['Server'], server_id: str) -> Optional['Server']:
        """
        Find the server object with the given ID in the list of server objects.

        Args:
            server_list (List[Server]): List of Server objects
            server_id (str): ID of the server to find

        Returns:
            Optional[Server]: The server object if found, None otherwise
        """
        for server in server_list:
            if server.server_id == server_id:
                return server
        return None

    def __eq__(self, other) -> bool:
        """
        Compare two Server objects for equality.

        Args:
            other (Server): Another Server object to compare with.

        Returns:
            bool: True if the two Server objects are equal, False otherwise.
        """
        if isinstance(other, Server):
            return (
                self.server_ip == other.server_ip and
                self.server_port == other.server_port and
                self.server_name == other.server_name and
                self.server_id == other.server_id and
                self.symmetric_key == other.symmetric_key
            )
        return False

#Client's property
class Lastseen:
    """ Part of the Client's Information """
    def __init__(self, year: int, month: int, day: int, hour:int, minute:int, second:int):
        self.year = year
        self.month = month
        self.day = day
        self.hour = hour
        self.minute = minute
        self.second = second
        self._validate_datetime()

    @classmethod
    def from_datetime(cls, datetime_obj: datetime.datetime):
        return cls(datetime_obj.year, datetime_obj.month, datetime_obj.day, datetime_obj.hour, datetime_obj.minute, datetime_obj.second)

    def _validate_datetime(self):
        try:
            datetime.datetime(self.year, self.month, self.day, self.hour, self.minute, self.second)
        except ValueError as e:
            raise ValueError("Invalid date or time.") from e

    #compare to other Lastseen object
    def __eq__(self, other):
        """
        Override the operator '=='

        Args:
            other (Lastseen): recieving other object of the same class

        Returns:
            boolean: True if both equals (have the sime date and time values)
        """
        if not isinstance(other, Lastseen):
            return False
        return (self.year, self.month, self.day, self.hour, self.minute, self.second) == \
               (other.year, other.month, other.day, other.hour, other.minute, other.second)

    def print_datetime(self):
        return f"{self.year}-{self.month:02d}-{self.day:02d} {self.hour:02d}:{self.minute:02d}:{self.second:02d}"
    
#part of Response 1603 - sending to the client an encrypted symmetric key between the server and the client.
class EncryptedKey:
    def __init__(self, encrypted_key_iv: bytes, encrypted_nonce: bytes, encrypted_server_key: bytes):
        self.encrypted_key_iv = encrypted_key_iv
        self.encrypted_nonce = encrypted_nonce
        self.encrypted_server_key = encrypted_server_key

    def pack(self) -> bytes:
        ''' Pack the components into a binary representation '''
        if len(self.encrypted_key_iv) != 16:
            raise ValueError("The encrypted key IV must be 16 bytes long")
        if len(self.encrypted_nonce) != 8:
            raise ValueError("The encrypted nonce must be 8 bytes long")
        if len(self.encrypted_server_key) != 32:
            raise ValueError("The encrypted server key must be 32 bytes long")

        return struct.pack('<16s8s32s', self.encrypted_key_iv, self.encrypted_nonce, self.encrypted_server_key)

    @classmethod
    def unpack(cls, data: bytes) -> 'EncryptedKey':
        ''' Unpack the binary representation into an EncryptedKey object '''
        if len(data) != 56:
            raise ValueError("The data must be 56 bytes long")

        encrypted_key_iv, encrypted_nonce, encrypted_server_key = struct.unpack('<16s8s32s', data)
        return cls(encrypted_key_iv, encrypted_nonce, encrypted_server_key)

#part of Response 1603 - sending to the client an encrypted ticket to pass to server.
class Ticket:
    def __init__(self, server_version: int, client_id: bytes, server_id: bytes, ticket_iv: bytes, aes_key: bytes, expiration_time: int):
        self.server_version = server_version
        self.client_id = client_id
        self.server_id = server_id
        self.creation_time = int(datetime.now(timezone.utc).timestamp())
        self.ticket_iv = ticket_iv
        self.aes_key = aes_key
        self.expiration_time = expiration_time
        
    # --------- pack / unpack ---------
    def pack(self) -> bytes:
        ''' Pack the Ticket object into bytes '''
        return struct.pack('<B16s16sQ16s32sQ',
                           self.server_version,
                           self.client_id,
                           self.server_id,
                           self.creation_time,
                           self.ticket_iv,
                           self.aes_key,
                           self.expiration_time)

    @classmethod
    def unpack(cls, data: bytes) -> 'Ticket':
        ''' Unpack bytes into a Ticket object '''
        unpacked_data = struct.unpack('<B16s16sQ16s32sQ', data)
        return cls(*unpacked_data)

    # --------- encrypt / decrypt ---------
    def encrypt(self, server_aes_key: bytes) -> bytes: #Special encrypt function because I'm encrypting the Ticket as whole and not each parameter
        ''' Encrypt the Ticket object using server_aes_key '''
        cipher = AES.new(server_aes_key, AES.MODE_CBC, self.ticket_iv)
        plaintext = self.pack()
        padded_plaintext = pad(plaintext, AES.block_size)
        return cipher.encrypt(padded_plaintext)
    
    @classmethod
    def from_ciphertext(cls, ciphertext: bytes, server_aes_key: bytes) -> 'Ticket':
        ''' Decrypt ciphertext using server_aes_key and create Ticket object '''
        cipher = AES.new(server_aes_key, AES.MODE_CBC, ciphertext[:16])
        decrypted_data = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
        return cls.unpack(decrypted_data)
      
class SymmetricKeyResponse:
    def __init__(self, client_id: bytes, encrypted_key: EncryptedKey, encrypted_ticket: bytes):
        self.client_id = client_id
        self.encrypted_key = encrypted_key
        self.encrypted_ticket = encrypted_ticket

    def pack(self) -> bytes:
        ''' Pack the SymmetricKeyResponse object into bytes '''
        client_id_len = len(self.client_id)
        packed_encrypted_key = self.encrypted_key.pack()
        return struct.pack(f'<16sHH', self.client_id, len(packed_encrypted_key), len(self.encrypted_ticket)) + packed_encrypted_key + self.encrypted_ticket  # Include the packed encrypted ticket data

    @classmethod
    def unpack(cls, data: bytes, server_aes_key: bytes) -> 'SymmetricKeyResponse':
        ''' Unpack bytes into a SymmetricKeyResponse object '''
        client_id, encrypted_key_len, encrypted_ticket_len = struct.unpack_from('<16sHH', data, 0)
        client_id = client_id[:16]  # Ensure client_id is 16 bytes
        encrypted_key_data = data[16:16+encrypted_key_len]
        encrypted_ticket_data = data[16+encrypted_key_len:]
        encrypted_key = EncryptedKey.unpack(encrypted_key_data)
        return cls(client_id, encrypted_key, encrypted_ticket_data)

    

    


