import struct
import datetime
import hashlib
from typing import Optional

class Payload:
    def __init__(self, client_id: str, version: str, code: str, payload: Optional[str]):
        self.client_id = client_id[:16]  # Limit to 16 bytes
        self.version = version[:1]  # Limit to 1 byte
        self.code = code[:2]  # Limit to 2 bytes
        self.payload_size = len(payload.encode('utf-8')) if payload else 0 # len() return int (= 4 bytes)
        self.payload = payload

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
    def unpack(cls, data: bytes) -> 'Payload':
        ''' class method to unpack data and creating new object \n
            'data' - bytes object (=usually Payload object that is after 'pack' method)\n
            return - new Payload object'''
        format_string = '<16s1s2sI'
        size_of_header = struct.calcsize(format_string)
        header = struct.unpack(format_string, data[:size_of_header])
        payload = data[size_of_header:]
        return cls(header[0].decode('utf-8'), header[1].decode('utf-8'), header[2].decode('utf-8'), payload.decode('utf-8'))
    

class Client:
    def __init__(self, id: str, name: str, password_hash: bytes, datetime_obj: datetime.datetime):
        """
        Creat Client's object

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
        pass #TODO: STOPPED HERE !

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