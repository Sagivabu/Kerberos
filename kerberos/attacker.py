# Sagiv Abu 206122459
# This file designed to implement an offline dictionary attack against the described protocol (Kerberos)

import hashlib
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# רעיון התוקף:
# 1. יש להריץ פעם אחת רגיל ולשמור 2 הודעות כקבועים בקובץ של התוקף
# 1.1. הודעה ראשונה - את המזהה של הסרבר והנונס (בעת בקשת מפתח לשרת הודעות) קוד בקשה 1027
# 1.2. הודעה שנייה - את 1603
# 2. יש לנסות לפענח עם קבוץ סמסאות את ה1603 ולהשוות לנונס של 1027 - אם שווה - מצאנו את הססמא
# 3. הערה: בפרוייקט שלי כבר הוספתי שכבת הגנה נוספת, הסולט, ולכן פה אצא בהנחה ויש לי אותו וכך הראה את החשיבות בו

# Fixed parameters #NOTE: XXX: This data came from user: viki (my wife) and password of '123456'
client_request_1027_payload = b"\xfa?\xd3\x17a\x92C\xa7\x84\xc2\x99\xaf\x84\x94\x1b\xf1\x85\x03\xb6\xd81(,\x9a"
auth_response_1603_payload = b"%\x1b\xfd\xe9\x1b\x99Jt\xa0\xecR\xd1J\x99\xf7)\xb5\xa8\x84\x85D\xe4\t\xa1\xa7G[f{\xd8\x0f\xbfch\xe5\xa0ci^\x86\xa9t\xec&T\x14\xd5\xc4K\xe8x4\xf2\xba\xb0\xc7\xba8\x16\x9e\xe4\x89\x872Q\xe1\xef\xff\xeag\xadVn\xda\xa2(\x00kBD\x18%\x1b\xfd\xe9\x1b\x99Jt\xa0\xecR\xd1J\x99\xf7)\xfa?\xd3\x17a\x92C\xa7\x84\xc2\x99\xaf\x84\x94\x1b\xf1\xe7\xc17f\x00\x00\x00\x00e9\x98k#\xc6\x11\x85\x05\x95!\xbb\xb1\xa5\xad\x13'\xf6\x9f\xe2\x92?\xad\xba\xb9\xdf\x027x&V\xc0\x08\x1d(\xecdT0?\xdaa_\x19\xd0\x99Akb\xb2\x9c|\xe8v\x88\xb6q\xbb\xfc\xce\x9f+\xd5s"

def decrypt_encryption_key_struct(data: bytes, key: bytes) -> tuple:
    """
    A function to decrypt Encrypted_Key object

    Args:
        data (bytes): Encrypted_Key packed as bytes
        key (bytes): The key to ddecrypt the object

    Returns:
        tuple: nonce, aes_key
    """
    try:
        # Extract IV
        iv = data[:16]

        # Decrypt the rest of the data
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(data[16:])
        
        # Remove padding - most likely to raise exception if decrypted_data was not decrypted properly
        unpadded_data = unpad(decrypted_data, AES.block_size)

        # Split decrypted data into nonce and AES key
        nonce = unpadded_data[:8]
        aes_key = unpadded_data[8:]

        return nonce, aes_key
    except Exception as e: # Decryption failed, most likely in the 'unpad' step
        # print(f"Decryption failed, key: '{key}' not match.\t{e}") 
        return None, None
        
def attacker_main():
    print(f"This is offline dictionary attack - I grab the next data from the connection between client and authentication server.")
    print(f"The data is:\n\t\
        Request 1027 - request for symmetric key for a server, the request include server_id, nonce\n\t\
        Respnse 1603 - response that include the symmetric key, and the nonce for validation")
    
    # !!! Assuming we got the next information:
    # !!! 1. The request for symmetric key: server_id , nonce
    # !!! 2. The response from auth server: client_id, Encrypted_key , Ticket
    # !!! 2.1. Encrypted_key composed of: Encrypted_key_IV, nonce(encrypted!), aes_key(encrypted!)
    # !!! 3. The SALT - the extra protection to derive the encryption key
    
    # Break the request:
    nonce = client_request_1027_payload[16:]         # NOTE: This parameter is important!
    
    # Break the response:
    encrypted_key = auth_response_1603_payload[16:80] # Unpack the encrypted key - 16+64 = 80
    
    # Prepare the passwords dictionary:
    dictionary = ['password', 'qwerty', 'letmein', 'username', 'blablabla', 'openucoil', '0000000', '123456', '9999999']
    
    # Try to decrypt the Encrypted_Key strutucre and export the 'nonce'
    for password in dictionary:
        # Create password_hash
        password_hash = hashlib.sha256(password.encode()).digest() 
        
        #NOTE: In my project I already added salt for extra protection. I will show how much easy it is without salt or if salt is revealed
        salt = b"Sagiv_Abu_206122459"
        
        # Create the encryption key
        guessed_encryption_key =  hashlib.pbkdf2_hmac('sha256', password_hash, salt, 100000)
        
        # Decrypt the Encrypted_Key object
        decrypted_nonce, decrypted_aes_key = decrypt_encryption_key_struct(data = encrypted_key, key=guessed_encryption_key)
        
        if not decrypted_nonce: # Decryption failed
            continue
        
        if decrypted_nonce == nonce:
            print(f"Password found: {password}")
            break
        else:
            continue

if __name__ == "__main__":
    attacker_main()