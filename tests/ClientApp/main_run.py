from kerberos.clientapp import ClientApp

if __name__ == "__main__":
    client = ClientApp("client", "password")
    
    while True:
        try:
            user_input = input("Enter command (e.g., 'get_key server_id', 'connect ip:port', 'set_password password', 'get_servers_list', 'add_server ip:port', 'send ip:port msg', or 'register'): ")
        except KeyboardInterrupt:
            print("\nExiting...")
            break

        client.handle_user_input(user_input)