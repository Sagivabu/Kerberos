DEFAULT_PORT = 1256
MIN_PORT_VALUE = 0
MAX_PORT_VALUE = 65535

def is_valid_port(port) -> bool:
    ''' check if port is valid '''
    try:
        port = int(port)
        return MIN_PORT_VALUE < port <= MAX_PORT_VALUE
    except ValueError:
        return False

def read_port(file_path: str) -> int:
    ''' get port.info file path and return the port in it'''
    try:
        with open(file_path, 'r') as file:
            content = file.read().strip()

            if is_valid_port(content):
                return int(content)
            else:
                print(f"Invalid port number in the file, selecting default port: '{DEFAULT_PORT}'.")
                return DEFAULT_PORT
 
    except FileNotFoundError:
        print(f"File not found: '{file_path}',selecting default port: '{DEFAULT_PORT}'.")
        return DEFAULT_PORT
    except Exception as e:
        print(f"An error occurred: {e}, \nselecting default port: '{DEFAULT_PORT}'.")
        return DEFAULT_PORT