import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from kerberos.utils.structs import Authenticator

#NOTE: Most of the decrypion functions are class methods in structs.py

def derive_client_key(password_hash: bytes, salt: bytes) -> bytes:
    """
    Create 'client_key' from password hash using a key derivation function (e.g., PBKDF2)

    Args:
        password_hash (bytes): Client's password_hash
        salt (bytes): client's salt

    Returns:
        bytes: return 'client_key' which based on the client's password_hash
    """
    return hashlib.pbkdf2_hmac('sha256', password_hash, salt, 100000)

def decrypt_authenticator(data: bytes, client_key: bytes) -> Authenticator:
    """ Decrypts the ciphertext into an Authenticator object using AES_CBC with the given client_key """
    iv = data[:16]  # Extract IV from the beginning of the data
    ciphertext = data[16:]
    
    cipher = AES.new(client_key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    return Authenticator.unpack(plaintext)