from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import hashlib

def generate_client_key(password_hash: bytes) -> bytes:
    """_summary_

    Args:
        password_hash (bytes): client's password_hash

    Returns:
        bytes: key based on the given password_hash
    """
    salt = b'Sagiv_Abu_206122459_Auth_Server' #salt - add uniqueness to the hashing process
    return hashlib.pbkdf2_hmac('sha256', password_hash, salt, 100000)

def generate_random_iv() -> bytes:
    """
    Generate a random Initialization Vector (IV)

    Returns:
        bytes: return 16 random bytes
    """
    return get_random_bytes(16)

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


