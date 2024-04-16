

from datetime import datetime


MIN_PORT_VALUE = 0
MAX_PORT_VALUE = 65535

def is_valid_port(port) -> bool:
    ''' check if port is valid '''
    try:
        port = int(port)
        return MIN_PORT_VALUE < port <= MAX_PORT_VALUE
    except ValueError:
        return False

def read_port(file_path: str, default_port: int) -> int:
    ''' get port.info file path and return the port in it'''
    try:
        with open(file_path, 'r') as file:
            content = file.read().strip()

            if is_valid_port(content):
                return int(content)
            else:
                print(f"Invalid port number in the file, selecting default port: '{default_port}'.")
                return default_port
 
    except FileNotFoundError:
        print(f"File not found: '{file_path}',selecting default port: '{default_port}'.")
        return default_port
    except Exception as e:
        print(f"An error occurred: {e}, \nselecting default port: '{default_port}'.")
        return default_port
    

def update_txt_file(file_path: str, string_to_write: str):
    """
    Append given string to the end of the text file.
    """
    try:
        with open(file_path, 'a') as file:
            file.write(string_to_write)
    except Exception as e:
        print(f"Failed to update txt file: '{file_path}', with the next string: '{string_to_write}'")
        raise

def read_txt_file(file_path: str) -> str:
    """
    Read given txt file

    Args:
        file_path (str): path to the required file

    Returns:
        str: string of the txt file
    """
    try:
        with open(file_path, 'r') as file:
            content = file.read()
        return content
    except Exception as e:
        print(f"Failed to read txt file: '{file_path}'")
        raise


def datetime_to_bytes(dt: datetime) -> bytes:
    """
    Convert datetime object to timestamp of 8 bytes (for further use)

    Args:
        dt (datetime): datetime object to convert to 8 bytes timestamp

    Returns:
        bytes: 8 bytes timestamp
    """
    # Convert the datetime object to a Unix timestamp
    timestamp = int(dt.timestamp())
    
    # Convert the timestamp to bytes (using little endian byte order)
    return timestamp.to_bytes(8, byteorder='little')
