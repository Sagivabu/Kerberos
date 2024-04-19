from kerberos.clientapp import ClientApp

# Example usage:
client = ClientApp("client", "password")

# Read servers info
servers_info = client.read_servers_info()
print("Servers Info:", servers_info)

# Add a new server
client.add_server_info("192.168.0.3", 8002)

# Read servers info again
servers_info = client.read_servers_info()
print("Updated Servers Info:", servers_info)