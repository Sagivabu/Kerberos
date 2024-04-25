import struct
import datetime
import hashlib
from typing import Optional, List
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from kerberos.utils.utils import  is_valid_port, is_valid_ip

RESPONSE_HEADER_SIZE = 7
REQUEST_HEADER_SIZE = 23

class ResponseStructure:
    def __init__(self, version: int, code: int, payload: Optional[bytes]) -> None:
        """
        Response format

        Args:
            version (int): kerberos protocol version
            code (int): Indicates the payload format which helps to decipher the payload later
            payload (bytes): the content to send
        """
         # Limit version to 1 byte
        if not 0 <= version <= 255:
            raise ValueError("Version must be a single byte (0-255)")
        self.version = version
        
        # Limit code to 2 bytes
        if not 0 <= code <= 65535:  # 2 bytes can represent integers from 0 to 65535
            raise ValueError("Code must be 2 bytes")
        self.code = code
        
        # Set payload_size
        if payload is None:
            self.payload_size = 0
        else:
            self.payload_size = len(payload)  # Use length of bytes
        self.payload = payload
    
    # ---------- PACK / UNPACK ----------
    def pack(self) -> bytes:
        """
        Pack the ResponseStructure object into a binary representation.

        Returns:
            bytes: Packed binary representation of the ResponseStructure object.
        """
        # Pack the data
        format_string = '<BHI'
        packed_data = struct.pack(format_string, self.version, self.code, self.payload_size)
        
        # Include payload if it exists
        if self.payload:
            packed_data += self.payload
        
        return packed_data

    @classmethod
    def unpack(cls, data: bytes) -> 'ResponseStructure':
        """
        Unpack binary data into a ResponseStructure object.

        Args:
            data (bytes): Binary data to unpack.

        Returns:
            ResponseStructure: Unpacked ResponseStructure object.
        """
        # Unpack the data
        format_string = '<BHI'
        version, code, payload_size = struct.unpack(format_string, data[:7])
        
        # Extract the payload
        payload = data[7:7 + payload_size]

        return cls(version, code, payload)

    # ---------- functions related to Specific Codes ----------
    def extract_client_id(self) -> str: # Code 1600 (Registration SUCCESS)
        """
        Extract and return client_id from payload

        Raises:
            ValueError: Does not contain ID (16 bytes length)

        Returns:
            str : Extracted ID
        """
        # Validate that the payload contains exactly 16 characters
        if not self.payload or len(self.payload) != 16:
            raise ValueError("Payload must contain exactly 16 characters")
        
        return self.payload.decode()
        
class RequestStructure:
    def __init__(self, client_id: bytes, version: int, code: int, payload: Optional[bytes]) -> None:
        """
        Request format

        Args:
            client_id (bytes): sender id (usually the client)
            version (str): kerberos protocol version
            code (int): Indicates the payload format which helps to decipher the payload later
            payload (bytes): the content to send
        """
        # Validate client_id
        if len(client_id) != 16:
            raise ValueError("Client ID must be exactly 16 bytes")
        self.client_id = client_id
        
        # Limit version to 1 byte
        if not 0 <= version <= 255:
            raise ValueError("Version must be a single byte (0-255)")
        self.version = version
        
        # Limit code to 2 bytes
        if not 0 <= code <= 65535:  # 2 bytes can represent integers from 0 to 65535
            raise ValueError("Code must be 2 bytes")
        self.code = code
        
        # Set payload_size
        if payload is None:
            self.payload_size = 0
        else:
            self.payload_size = len(payload)  # Use length of bytes
        self.payload = payload
         
    # ---------- PACK / UNPACK ----------
    def pack(self) -> bytes:
        """
        Pack the RequestStructure object into a binary representation.

        Returns:
            bytes: Packed binary representation of the RequestStructure object.
        """
        # Pack the data
        format_string = '<16sBHI'
        packed_data = struct.pack(format_string, self.client_id, self.version, self.code, self.payload_size)
        
        # Include payload if it exists
        if self.payload:
            packed_data += self.payload
        
        return packed_data

    @classmethod
    def unpack(cls, data: bytes) -> 'RequestStructure':
        """
        Unpack binary data into a RequestStructure object.

        Args:
            data (bytes): Binary data to unpack.

        Returns:
            RequestStructure: Unpacked RequestStructure object.
        """
        # Unpack the data
        format_string = '<16sBHI'
        client_id, version, code, payload_size = struct.unpack(format_string, data[:23])
    
        # Extract the payload
        payload = data[23:23 + payload_size]

        return cls(client_id, version, code, payload)
    
    # ---------- functions related to Specific Codes ----------
    def extract_name_password(self) -> tuple[str, str]: # Code 1024 (Registration)
        """
        Validate it is "Registration" request and extract name and password from payload

        Returns:
            tuple[str, str]: return (name, password) as tuple
        """
        if not self.payload:
            raise ValueError("Payload is None")
        
        #change payload to str
        payload = self.payload.decode()
        
        # Find the index of the first null terminator in the payload
        null_index = payload.find('\x00')
        if null_index == -1:
            raise ValueError("Payload does not contain null terminator")

        # Extract the name and password from the payload
        parts = payload.split('\x00') #separate by null terminated character
        non_empty_parts = [part for part in parts if part]  # Filter out empty strings
        if len(non_empty_parts) != 2: #VALIDATION: only 2 strings should exists
            raise ValueError("Payload does not contain exactly two strings")

        name = non_empty_parts[0].strip()
        password = non_empty_parts[1].strip()
        return name, password
    
    def extract_server_id_nonce(self) -> tuple[str, str]:
        """
        Validate it is "Symmetric key for a server" request and extract server_id and nonce from payload

        Returns:
            tuple[str, str]: return (server_id, nonce) as tuple of strings
        """
        if not self.payload:
            raise ValueError("Payload is None")
        
        #change payload to str
        payload = self.payload.decode()
        
        # Find the index of the first null terminator in the payload
        null_index = payload.find('\x00')
        if null_index == -1:
            raise ValueError("Payload does not contain null terminator")

        # Extract the server ID and nonce from the payload
        parts = payload.split('\x00')
        non_empty_parts = [part for part in parts if part]  # Filter out empty strings
        if len(non_empty_parts) != 2:
            raise ValueError("Payload does not contain exactly two parameters")

        server_id = non_empty_parts[0]
        nonce = non_empty_parts[1]

        # Validate the lengths of the extracted parameters
        if len(server_id) != 16:
            raise ValueError("Server ID must be exactly 16 bytes")
        if len(nonce) != 8:
            raise ValueError("Nonce must be exactly 8 bytes")

        return server_id, nonce
    
    def extract_server_name_symmetric_key(self) -> tuple[str, str]:
        """
        Extract server name and symmetric key from payload.

        Args:
            payload (str): Payload string containing server name and symmetric key.

        Returns:
            tuple[str, str]: Tuple containing server name and symmetric key.
        """
        if not self.payload:
            raise ValueError("Payload is None")
        
        #change payload to str
        payload = self.payload.decode()
        
        # Split payload by null terminator to separate server name and symmetric key
        parts = payload.split('\x00')
        non_empty_parts = [part for part in parts if part]  # Filter out empty strings

        # Validate the number of parts
        if len(non_empty_parts) != 2:
            raise ValueError("Payload does not contain exactly two parameters")

        # Extract server name and symmetric key
        server_name = non_empty_parts[0]
        symmetric_key = non_empty_parts[1]

        # Validate the length of the symmetric key
        if len(symmetric_key) != 32:
            raise ValueError("Symmetric key must be exactly 32 bytes")

        return server_name, symmetric_key
    
class Client:
    def __init__(self, id: bytes, name: str, password_hash: bytes, datetime_obj: datetime) -> None:
        """
        Create Client's object

        Args:
            id (bytes): 16 bytes of id 
            name (str): 255 characters of name
            password_hash (bytes): SHA-256 password hash (32 bytes)
            datetime_obj (datetime.datetime): datetime object including: year, month, day, hour, minute, second
        """
         # Limit id to 16 bytes
        if  len(id) != 16:
            raise ValueError("ID must be exactly 16 bytes")
        self.id = id

        # Limit name to 255 characters
        # Limit server_name to 255 characters
        if len(name) > 255:
            raise ValueError("Name must be 255 characters or less")
        self.name = name

        # Ensure password_hash is exactly 32 bytes
        if len(password_hash) != 32:
            raise ValueError("Password hash must be 32 bytes")
        self.password_hash = password_hash

        # Validate datetime_obj
        try:
            self.lastseen = Lastseen.from_datetime(datetime_obj)
        except ValueError as e:
            raise ValueError("Invalid datetime object") from e
        # Convert user_id string to bytes (UTF-8 encoding)

    @classmethod
    def from_plain_password(cls, id: bytes, name: str, password: str, datetime_obj: datetime):
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
        password_hash = self.password_hash.hex()
        lastseen_string = self.lastseen.print_datetime()
        id = self.id.hex()
        the_row = f"{id}:{self.name}:{password_hash}:{lastseen_string}"
        return the_row
    
    @staticmethod
    def find_client(client_list: List['Client'], client_id: bytes) -> Optional['Client']:
        """
        Find the client object with the given ID in the list of client objects.

        Args:
            client_list (List[Client]): List of Client objects
            client_id (bytes): ID of the client to find

        Returns:
            Optional[Client]: The client object if found, None otherwise
        """
        for client in client_list:
            if client.id == client_id:
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
    def __init__(self, server_ip: str, server_port: int, server_name: str, server_id: str, symmetric_key: str, version: int = 24):
        """
        Create a Server object.

        Args:
            server_ip (str): The server's IP address.
            server_port (int): The server's port number.
            server_name (str): The server's name.
            server_id (str): The server's unique ID in ASCII where every 2 chars represent 8 bits in hex.
            symmetric_key (str): The long-term symmetric key for the server in Base64 format.
        """
        # Validate server IP using is_valid_ip function
        if not is_valid_ip(server_ip):
            raise ValueError("Invalid server IP address format")
        self.server_ip = server_ip

        # Validate server port using is_valid_port function
        if not is_valid_port(server_port):
            raise ValueError("Invalid server port")
        self.server_port = server_port

        # Limit server_name to 255 characters
        if len(server_name) > 255:
            raise ValueError("Server name must be 255 characters or less")
        self.server_name = server_name

        # Validate server_id length (16 bytes)
        if len(server_id) != 16:
            raise ValueError("Server ID must be 16 bytes long")
        self.server_id = server_id

        # Validate symmetric_key length (32 bytes)
        if len(symmetric_key) != 32:
            raise ValueError("Symmetric key must be 32 bytes long")
        self.symmetric_key = symmetric_key

        # Validate version as a single byte (0-255)
        if not 0 <= version <= 255:
            raise ValueError("Version must be a single byte (0-255)")

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

    def set_version(self, version: int) -> None:
        self.version = version

class ServerInList:
    def __init__(self, id: bytes, name: str, ip: str, port: int):
        """
        Create a ServerInList object.

        Args:
            id (bytes): The server's ID (16 bytes).
            name (str): The server's name (up to 255 characters).
            ip (str): The server's IP address (4 bytes in dotted decimal format).
            port (int): The server's port number (2 bytes).
        """
        # Verify ID length
        if len(id) != 16:
            raise ValueError("Server ID must be exactly 16 bytes")
        self.id = id

        # Verify Name length
        if len(name) > 255:
            raise ValueError("Server name exceeds 255 characters")
        self.name = name

        # Verify IP format
        if not is_valid_ip(ip):
            raise ValueError("Invalid IP address format")
        self.ip = ip

        # Verify Port range
        if not is_valid_port(port):
            raise ValueError("Port must be a 2-byte unsigned integer (0-65535)")
        self.port = port

    def pack(self) -> bytes:
        """
        Pack the ServerInList object into a binary representation.

        Returns:
            bytes: Packed binary data.
        """
        # Define the format string for packing the data
        format_string = f'<16sB{len(self.name)}s4sH'
        
        # Pack the data into bytes
        packed_data = struct.pack(format_string,
                                  self.id,
                                  len(self.name),
                                  self.name.encode('utf-8'),
                                  self.ip.encode('utf-8'),
                                  self.port)
        
        return packed_data

    @classmethod
    def unpack(cls, data: bytes) -> 'ServerInList':
        """
        Unpack binary data into a ServerInList object.

        Args:
            data (bytes): Binary data to unpack.

        Returns:
            ServerInList: Unpacked ServerInList object.
        """
        # Define the format string for unpacking the data
        format_string = '<16sB255s4sH'
        
        # Unpack the data into individual fields
        id, name_len, name_bytes, ip_bytes, port = struct.unpack(format_string, data)
        
        # Decode the name and IP fields
        name = name_bytes[:name_len].decode('utf-8')
        ip = '.'.join(str(byte) for byte in ip_bytes)
        
        return cls(id, name, ip, port)

    def __str__(self):
        """Print the ServerInList object in the specified format."""
        return f"{self.name} - {self.ip}:{self.port} - {self.id.hex().upper()}"

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
    def from_datetime(cls, datetime_obj: datetime):
        return cls(datetime_obj.year, datetime_obj.month, datetime_obj.day, datetime_obj.hour, datetime_obj.minute, datetime_obj.second)

    def _validate_datetime(self):
        try:
            datetime(self.year, self.month, self.day, self.hour, self.minute, self.second)
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
    def __init__(self, iv: bytes, nonce: bytes, aes_key: bytes):
        """
        Represents an encrypted key structure.

        Args:
            iv (bytes): Initialization Vector for encryption.
            nonce (bytes): Nonce value to be encrypted.
            aes_key (bytes): AES key to be encrypted.
        """
        # Validate IV
        if len(iv) != 16:
            raise ValueError("IV must be exactly 16 bytes")
        
        # Validate Nonce
        if len(nonce) != 8:
            raise ValueError("Nonce must be exactly 8 bytes")

        # Validate AES Key
        if len(aes_key) != 32:
            raise ValueError("AES key must be exactly 32 bytes")

        self.iv = iv
        self.nonce = nonce
        self.aes_key = aes_key

    def pack(self, key: bytes) -> bytes:
        """
        Pack the EncryptedKey object into a binary representation,
        encrypting the nonce and AES key with the given key and IV.

        Args:
            key (bytes): Symmetric key for encryption.

        Returns:
            bytes: Encrypted binary representation of the EncryptedKey object.
        """
        # Encrypt nonce and AES key together
        cipher = AES.new(key, AES.MODE_CBC, self.iv)
        plaintext = self.nonce + self.aes_key
        padded_plaintext = pad(plaintext, AES.block_size)
        encrypted_data = cipher.encrypt(padded_plaintext)

        # Return IV + Encrypted data
        return self.iv + encrypted_data

    @classmethod
    def unpack(cls, data: bytes, key: bytes) -> 'EncryptedKey':
        """
        Unpack binary data into an EncryptedKey object, decrypting the data
        using the provided key.

        Args:
            data (bytes): Binary data to unpack.
            key (bytes): Symmetric key for decryption.

        Returns:
            EncryptedKey: Unpacked EncryptedKey object.
        """
        # Ensure data is at least 32 bytes (IV + encrypted data)
        if len(data) < 32:
            raise ValueError("Invalid data length for unpacking EncryptedKey")

        # Extract IV
        iv = data[:16]

        # Decrypt the rest of the data
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(data[16:])
        
        # Remove padding
        unpadded_data = unpad(decrypted_data, AES.block_size)

        # Split decrypted data into nonce and AES key
        nonce = unpadded_data[:8]
        aes_key = unpadded_data[8:]

        return cls(iv, nonce, aes_key)
     
#part of Response 1603 - sending to the client an encrypted ticket to pass to server.
class Ticket:
    def __init__(self, server_version: int, client_id: bytes, server_id: bytes, creation_time: datetime, ticket_iv: bytes, aes_key: bytes, expiration_time: datetime):
        """ Ticket structure for client-server communication """
        if not 0 <= server_version <= 255:
            raise ValueError("Server version must be a single byte (0-255)")
        if len(client_id) != 16:
            raise ValueError("Client ID must be exactly 16 bytes")
        if len(server_id) != 16:
            raise ValueError("Server ID must be exactly 16 bytes")
        if len(ticket_iv) != 16:
            raise ValueError("Ticket IV must be exactly 16 bytes")
        if len(aes_key) != 32:
            raise ValueError("AES key must be exactly 32 bytes")
        if not isinstance(creation_time, datetime):
            raise ValueError("Creation time must be a datetime object")
        if not isinstance(expiration_time, datetime):
            raise ValueError("Expiration time must be a datetime object")

        self.server_version = server_version
        self.client_id = client_id
        self.server_id = server_id
        self.creation_time = creation_time
        self.ticket_iv = ticket_iv
        self.aes_key = aes_key
        self.expiration_time = expiration_time
        
    def pack(self, key: bytes) -> bytes:
        """
        Pack the Ticket object into a binary representation,
        encrypting the AES key and expiration time with the given key and with self IV.

        Args:
            key (bytes): Symmetric key for encryption.

        Returns:
            bytes: Encrypted binary representation of the Ticket object.
        """
        # Convert creation_time and expiration_time to 8-byte representations
        creation_time_bytes = int(self.creation_time.timestamp()).to_bytes(8, byteorder='little', signed=False)
        expiration_time_bytes = int(self.expiration_time.timestamp()).to_bytes(8, byteorder='little', signed=False)

        # Pack the data
        packed_data = struct.pack('<B16s16s8s16s', self.server_version, self.client_id, self.server_id, creation_time_bytes, self.ticket_iv)

        # Encrypt AES key and expiration_time with the provided key and IV
        cipher = AES.new(key, AES.MODE_CBC, self.ticket_iv)
        aes_key_exp_time = self.aes_key + expiration_time_bytes  # Combine both for encryption
        padded_data = pad(aes_key_exp_time, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)

        packed_data += encrypted_data

        return packed_data
    
    @classmethod
    def unpack(cls, data: bytes, key: bytes) -> 'Ticket':
        """
        Unpack binary data into a Ticket object,
        decrypting the AES key and expiration time with the given key.

        Args:
            data (bytes): Encrypted binary data to unpack.
            key (bytes): Symmetric key for decryption.

        Returns:
            Ticket: Unpacked Ticket object.
        """
        # Unpack the fixed-length data fields
        unpacked_data = struct.unpack('<B16s16s8s16s', data)

        # Extract fields from unpacked data
        server_version, client_id, server_id, creation_time_bytes, ticket_iv = unpacked_data

        # Extract the remaining bytes for encrypted_data
        encrypted_data_length = len(data) - struct.calcsize('<B16s16s8s16s')
        encrypted_data = data[-encrypted_data_length:]

        # Decrypt AES key and expiration_time with the provided key and IV
        cipher = AES.new(key, AES.MODE_CBC, ticket_iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        
        # Extract AES key and expiration_time
        aes_key = decrypted_data[:32]
        expiration_time_bytes = decrypted_data[32:]
        
        # Convert creation_time and expiration_time from bytes
        creation_time = datetime.fromtimestamp(int.from_bytes(creation_time_bytes, byteorder='little'))
        expiration_time = datetime.fromtimestamp(int.from_bytes(expiration_time_bytes, byteorder='little'))

        return cls(server_version, client_id, server_id, creation_time, ticket_iv, aes_key, expiration_time)
       
class SymmetricKeyResponse:
    def __init__(self, client_id: bytes, encrypted_key: bytes, ticket: bytes):
        """
        Represent the response in 'Symmetric Key' request to Auth server.

        Args:
            client_id (bytes): client's id in 16 bytes
            encrypted_key (bytes): packed 'EncryptedKey' object
            ticket (bytes): packed 'Ticket' object
        """
        # Validate client_id length (16 bytes)
        if len(client_id) != 16:
            raise ValueError("Client ID must be 16 bytes long")
        self.client_id = client_id
        
        self.encrypted_key = encrypted_key
        self.ticket = ticket

    def pack(self) -> bytes:
        """ Pack the SymmetricKeyResponse object into a binary representation """
        # Pack the client ID, encrypted key, and ticket
        packed_client_id = self.client_id
        packed_encrypted_key = self.encrypted_key
        packed_ticket = self.ticket

        # Combine the packed data
        packed_data = packed_client_id + packed_encrypted_key + packed_ticket
        
        return packed_data

    @classmethod
    def unpack(cls, data: bytes) -> 'SymmetricKeyResponse':
        """ Unpack binary data into a SymmetricKeyResponse object """
        # Unpack the client ID
        client_id = data[:16]
        # Unpack the encrypted key
        encrypted_key = data[16:72]
        # Unpack the ticket
        ticket = data[72:]
        
        # Create a new SymmetricKeyResponse object with the unpacked data
        return cls(client_id, encrypted_key, ticket)

class Authenticator:
    def __init__(self, iv: bytes, version: int, client_id: bytes, server_id: bytes, creation_time: bytes):
        """
        Authenticator that the client creates to send to the server. All parameters (except the IV) go for encryption.

        Args:
            iv (bytes): IV to encrypt the next parameters
            version (int): server version
            client_id (bytes): client id
            server_id (bytes): target server id
            creation_time (bytes): creation time
        """
        self.iv = iv
        self.version = version
        self.client_id = client_id
        self.server_id = server_id
        self.creation_time = creation_time

    def pack(self) -> bytes:
        """ Pack the Authenticator object into a binary representation """
        if len(self.iv) != 16:
            raise ValueError("IV must be exactly 16 bytes")
        if len(self.client_id) != 16:
            raise ValueError("Client ID must be exactly 16 bytes")
        if len(self.server_id) != 16:
            raise ValueError("Server ID must be exactly 16 bytes")
        if len(self.creation_time) != 8:
            raise ValueError("Creation time must be exactly 8 bytes")
        if not 0 <= self.version <= 255:
            raise ValueError("Version must be a single byte (0-255)")

        return struct.pack('<16sB16s16s8s', self.iv, self.version, self.client_id, self.server_id, self.creation_time)

    @classmethod
    def unpack(cls, data: bytes) -> 'Authenticator':
        """ Unpack binary data into an Authenticator object """
        if len(data) != 57:  # 16 + 1 + 16 + 16 + 8 = 57 bytes
            raise ValueError("Invalid data length for unpacking Authenticator")

        iv, version, client_id, server_id, creation_time = struct.unpack('<16sB16s16s8s', data)
        # Convert bytes back to strings
        client_id_str = client_id
        server_id_str = server_id
        return cls(iv, version, client_id_str, server_id_str, creation_time)

class EncryptedMessage:
    def __init__(self, message_iv: bytes, message_content: str):
        """
        Create an EncryptedMessage object. (client -> msg server)

        Args:
            message_iv (bytes): IV for message encryption.
            message_content (str): Content of the message to be encrypted.
        """
        # Validate message IV length (16 bytes)
        if len(message_iv) != 16:
            raise ValueError("Message IV must be 16 bytes long")
        self.message_iv = message_iv
        self.message_content = message_content

    def pack(self, aes_key: bytes) -> bytes:
        """
        Pack the EncryptedMessage object into a binary representation.

        Args:
            aes_key (bytes): AES key for encryption.

        Returns:
            bytes: Packed binary data.
        """
        # Encrypt message content
        message_bytes = self.message_content.encode()
        cipher = AES.new(aes_key, AES.MODE_CBC, self.message_iv)
        padded_content = pad(message_bytes, AES.block_size)
        encrypted_content = cipher.encrypt(padded_content)

        # Get the size of the encrypted content
        message_size = len(encrypted_content).to_bytes(4, byteorder='little')

        # Pack the data
        packed_data = struct.pack('<16s4s', self.message_iv, message_size) + encrypted_content
        return packed_data

    @classmethod
    def unpack(cls, data: bytes, aes_key: bytes) -> 'EncryptedMessage':
        """
        Unpack binary data into an EncryptedMessage object.

        Args:
            data (bytes): Binary data to unpack.
            aes_key (bytes): AES key for decryption.

        Returns:
            EncryptedMessage: Unpacked EncryptedMessage object.
        """
        # Unpack the IV and message size
        message_iv, message_size = struct.unpack('<16s4s', data[:20])
        message_size = int.from_bytes(message_size, byteorder='little')

        # Extract the encrypted content
        encrypted_content = data[20:20+message_size]

        # Decrypt the message content
        cipher = AES.new(aes_key, AES.MODE_CBC, message_iv)
        decrypted_content = cipher.decrypt(encrypted_content)

        # Remove padding
        unpadded_content = unpad(decrypted_content, AES.block_size).decode()

        return cls(message_iv, unpadded_content)


