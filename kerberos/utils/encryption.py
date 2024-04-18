import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

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

def encrypt_with_aes_cbc(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext using AES-CBC with the given key and IV

    Args:
        key (bytes): usually the client_key
        iv (bytes): random 16 bytes
        plaintext (bytes): the target to encrypt

    Returns:
        bytes: encrypted text "ciphertext"
    """
    # 
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext


