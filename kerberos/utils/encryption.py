import os
import hashlib
import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

from kerberos.utils.structs import Authenticator, EncryptedKey, Ticket

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

# ---------- EncryptedKey ----------
def encrypt_encrypted_key(encrypted_key: EncryptedKey, key: bytes) -> bytes: 
    """ Encrypts an EncryptedKey object using AES_CBC with the given key """ #not in used
    if len(encrypted_key.encrypted_key_iv) != 16:
        raise ValueError("The IV must be 16 bytes long")
    if len(encrypted_key.encrypted_nonce) != 8:
        raise ValueError("The encrypted nonce must be 8 bytes long")
    if len(encrypted_key.encrypted_server_key) != 32:
        raise ValueError("The encrypted server key must be 32 bytes long")

    cipher = AES.new(key, AES.MODE_CBC, encrypted_key.encrypted_key_iv)
    plaintext = encrypted_key.pack()
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return encrypted_key.encrypted_key_iv + ciphertext  # Prepend IV to ciphertext

# ---------- Ticket ----------
def encrypt_ticket(ticket: 'Ticket', key: bytes) -> bytes:
    """ Encrypts only the 'encrypted_aes_key' and 'encrypted_expiration_time' fields of a Ticket object """ #not in used
    if len(ticket.ticket_iv) != 16:
        raise ValueError("The ticket IV must be 16 bytes long")
    if len(ticket.encrypted_aes_key) != 32:
        raise ValueError("The encrypted AES key must be 32 bytes long")
    if len(ticket.encrypted_expiration_time) != 8:
        raise ValueError("The encrypted expiration time must be 8 bytes long")
    
    # Pack the non-encrypted fields
    packed_data = struct.pack('<B16s16s8s', ticket.server_version, ticket.client_id, ticket.server_id, ticket.creation_time)
    
    # Encrypt the encrypted fields
    cipher = AES.new(key, AES.MODE_CBC, ticket.ticket_iv)
    encrypted_aes_key = cipher.encrypt(ticket.encrypted_aes_key)
    encrypted_expiration_time = cipher.encrypt(ticket.encrypted_expiration_time)
    
    # Concatenate everything
    packed_data += ticket.ticket_iv + encrypted_aes_key + encrypted_expiration_time
    
    return packed_data

# ---------- Authenticator ----------
def encrypt_authenticator(authenticator: Authenticator, client_key: bytes) -> bytes:
    """ Encrypts the Authenticator object using AES_CBC with the given client_key """
    cipher = AES.new(client_key, AES.MODE_CBC, authenticator.iv)
    plaintext = authenticator.pack()
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return authenticator.iv + ciphertext  # Prepend IV to ciphertext