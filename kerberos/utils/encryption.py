import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from kerberos.utils.structs import Authenticator

# NOTE: Most of the encryption functions are class method in structs.py


def derive_encryption_key(based_on: bytes) -> bytes:
    """
    Derive a key for encryption (e.g 'client_key', 'msg_server_key')

    Args:
        based_on (bytes): a parameter to based the key on (e.g: client's password_hash, server's symmetric_key)

    Returns:
        bytes: they encryption key
    """
    salt = b'Sagiv_Abu_206122459_Auth_Server' #salt - add uniqueness to the hashing process
    return hashlib.pbkdf2_hmac('sha256', based_on, salt, 100000)

def generate_random_iv() -> bytes:
    """
    Generate a random Initialization Vector (IV)

    Returns:
        bytes: return 16 random bytes
    """
    return get_random_bytes(16)

def generate_aes_key() -> bytes:
    """Generate a random AES key of 32 bytes"""
    return os.urandom(32)

# ---------- Authenticator ----------
def encrypt_authenticator(authenticator: Authenticator, client_key: bytes) -> bytes:
    """ Encrypts the Authenticator object using AES_CBC with the given client_key """
    cipher = AES.new(client_key, AES.MODE_CBC, authenticator.iv)
    plaintext = authenticator.pack()
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return authenticator.iv + ciphertext  # Prepend IV to ciphertext