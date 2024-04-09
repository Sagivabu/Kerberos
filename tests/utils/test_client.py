from dataclasses import dataclass
import datetime
import hashlib
from kerberos.utils.structs import Client, Lastseen

@dataclass
class Test_client():
    id = "1234567890123456"  # ID as a string
    name = "Sagiv Abu"
    password = "supersecret"
    datetime_object = datetime.datetime.now()

    #@property
    def test(self):
        print(f"Creating Client's object using the next parameters:\n\tid = ;{self.id};\n\tname = {self.name}\n\tpassword = {self.password}\n\tlastseen = {self.datetime_object}")
        client = Client.from_plain_password(self.id, self.name, self.password, self.datetime_object)
        print(f"Client object created with:\n\tid = ;{client.id};\n\tname = {client.name}\n\tpassword_hash = {client.password_hash}\n\tlastseen = {client.lastseen.print_datetime()}")
        id_bytes = self.id.encode('utf-8')[:16]
        password_hash = hashlib.sha256(self.password.encode()).digest()
        lastseen_object = Lastseen.from_datetime(self.datetime_object)

        #test the extracted parameters
        if(id_bytes == client.id): print(f"Correct id")
        else: print(f"Incorrect id")
        if(self.name == client.name): print(f"Correct name")
        else: print(f"Incorrect name")
        if(password_hash == client.password_hash): print(f"Correct password_hash")
        else: print(f"Incorrect password_hash")
        if(lastseen_object == client.lastseen): print(f"Correct lastseen")
        else: print(f"Incorrect lastseen")
    
    
def test():
    Test_client().test()

test()
