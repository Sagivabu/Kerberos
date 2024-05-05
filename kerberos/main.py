# Sagiv Abu 206122459

import time
import threading
from kerberos.authserver.AuthServer import AuthServer
from kerberos.msgserver.MsgServer import MsgServer
from kerberos.clientapp.ClientApp import ClientApp


def main():
    try:
        auth_server = AuthServer()
        auth_server_thread = threading.Thread(target=auth_server.run)
        auth_server_thread.start()
        time.sleep(1)
        
        msg_server = MsgServer()
        msg_server_thread = threading.Thread(target=msg_server.run, args='n')
        msg_server_thread.start()
        time.sleep(1)
        
        client = ClientApp()
        while True:
            try:
                user_input = input("\nEnter command from list:\
                                \n'get_key ip:port server_id'\
                                \n'connect ip:port'\
                                \n'disconnect ip:port\
                                \n'set_password password'\
                                \n 'get_servers_list'\
                                \n'add_server ip:port'\
                                \n'send ip:port msg'\
                                \n'register'\
                                \nEnter 'F' to finish process: ")
                if user_input in ['f','F']:
                    print("\nFinishing...")
                    break
            except KeyboardInterrupt:
                print("\nExiting...")
                break

            client.handle_user_input(user_input)
            
        # Monkeys tests?
        pass
    except Exception as e:
        print(f"ERROR occured while running 'main' function to test all the flow.\t{e}")

if __name__ == "__main__":
    main()  # This function will only be called if the script is run directly