import subprocess
import time
from kerberos.authserver.AuthServer import AuthServer
from kerberos.msgserver.MsgServer import MsgServer
from kerberos.clientapp.ClientApp import ClientApp


def main():
    try:
        # Upload Authentication Server in s new console
        subprocess.Popen(['python', '"C:/git/Kerberos/kerberos/authserver/AuthServer.py"'], creationflags=subprocess.CREATE_NEW_CONSOLE)
        
        # Upload 2 Clients
            # Register both
            # Ask for symmetric key for server 1
            # Send symmetric key
            # Send a message
            # Down and upload the same client (no need for registratrion)
        
        # Upload 2 Message Servers
            # Register both
        print('hi')
        time.sleep(25)
            
        # Monkeys tests?
        pass
    except Exception as e:
        print(f"ERROR occured while running 'main' function to test all the flow.\t{e}")

if __name__ == "__main__":
    main()  # This function will only be called if the script is run directly