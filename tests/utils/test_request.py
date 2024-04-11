from dataclasses import dataclass
from kerberos.utils.structs import Request

@dataclass
class Test_Request():
    client_id = '123456789ABCDEFG'
    version = '1'
    code = 'AB'
    payload = f"This message is from client_id '{client_id}' with version '{version}' and code '{code}'."

    #@property
    def test(self):
        pl = Request(client_id=self.client_id , version=self.version, code=self.code, payload=self.payload)
        print(f"Encrypting the next payload:\n\tclient_id = ;{self.client_id};\n\tversion = {self.version}\n\tcode = {self.code}\n\tpayload = {self.payload}")
        objectbytes = pl.pack()
        newpl = pl.unpack(objectbytes)
        print(f"Payload decryption:\n\tclient_id = ;{newpl.client_id};\n\tversion = {newpl.version}\n\tcode = {newpl.code}\n\tpayload = {newpl.payload}")

        #test the extracted parameters
        if(self.client_id == newpl.client_id): print(f"Correct client_id")
        else: print(f"Incorrect client_id")
        if(self.version == newpl.version): print(f"Correct version")
        else: print(f"Incorrect version")
        if(self.code == newpl.code): print(f"Correct code")
        else: print(f"Incorrect code")
        if(self.payload == newpl.payload): print(f"Correct payload")
        else: print(f"Incorrect payload")
    
    
def test():
    Test_Request().test()

test()



        