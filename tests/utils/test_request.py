from dataclasses import dataclass
from kerberos.utils.structs import RequestStructure

@dataclass
class Test_Request():
    client_id = '123456789ABCDEFG'
    version = '24'
    code = 'AB'
    payload = f"This message is from client_id '{client_id}' with version '{version}' and code '{code}'."

    #@property
    def test(self):
        req = RequestStructure(client_id=self.client_id , version=self.version, code=self.code, payload=self.payload)
        print(f"Encrypting the next payload:\n\tclient_id = ;{self.client_id};\n\tversion = {self.version}\n\tcode = {self.code}\n\tpayload = {self.payload}")
        objectbytes = req.pack()
        newreq = req.unpack(objectbytes)
        print(f"Payload decryption:\n\tclient_id = ;{newreq.client_id};\n\tversion = {newreq.version}\n\tcode = {newreq.code}\n\tpayload = {newreq.payload}")

        #test the extracted parameters
        if(self.client_id == newreq.client_id): print(f"Correct client_id")
        else: print(f"Incorrect client_id")
        if(self.version == newreq.version): print(f"Correct version")
        else: print(f"Incorrect version")
        if(self.code == newreq.code): print(f"Correct code")
        else: print(f"Incorrect code")
        if(self.payload == newreq.payload): print(f"Correct payload")
        else: print(f"Incorrect payload")
    
    
def test():
    Test_Request().test()

test()



        