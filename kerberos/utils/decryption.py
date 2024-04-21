from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import struct
from kerberos.utils.structs import EncryptedKey, Ticket, Authenticator

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

def derive_msg_server_key(auth_aes_key: bytes, salt: bytes) -> bytes:
    """
    Create 'msg_server_key' from the symmetric key with the auth_server using a key derivation function (e.g., PBKDF2)

    Args:
        auth_aes_key (bytes): symmetric key in common to msg_server <=> auth_server
        salt (bytes): server's salt

    Returns:
        bytes: return 'msg_server_key' which based on the server aes_key
    """
    return hashlib.pbkdf2_hmac('sha256', auth_aes_key, salt, 100000)

def decrypt_with_aes_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-CBC with the given key and IV

    Args:
        key (bytes): they key that encrypted the ciphertext (usually the 'client_key')
        iv (bytes): the IV used to encrypt the ciphertext
        ciphertext (bytes): the text to decrypt

    Returns:
        bytes: plain_text
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

def server_decrypt_ticket(ticket_iv: bytes, encrypted_expiration_time: bytes, encrypted_aes_key: bytes, auth_aes_key: bytes, salt: bytes) -> tuple[bytes,bytes]:
    """
    Function that helps the msg server to decrypt 'Ticket' object's parameters, which are 'encrypted_expiration_time' and 'encrypted_aes_key' (AES_key)

    Args:
        ticket_iv (bytes): IV that encrypted the parameters
        encrypted_expiration_time (bytes): Expiration time from auth server
        encrypted_aes_key (bytes): AES_key between the client and the msg_server
        auth_aes_key (bytes): AES_key between the auth_server and the msg_server
        salt (bytes): msg server's own salt

    Returns:
        tuple[bytes,bytes]: (decrypted_expiration_time, decrypted_aes_key)
    """
    # Derive msg server key based on the server's symmetric key
    msg_server_key = derive_msg_server_key(auth_aes_key, salt) 
    
    # Decrypt the expiration_time *first* then the aes_key using the IV and msg_server_key
    decrypted_expiration_time = decrypt_with_aes_cbc(msg_server_key, ticket_iv, encrypted_expiration_time)
    decrypted_aes_key = decrypt_with_aes_cbc(msg_server_key, ticket_iv, encrypted_aes_key)
    
    return decrypted_expiration_time, decrypted_aes_key

def decrypt_encrypted_key(data: bytes, key: bytes) -> EncryptedKey:
    """ Decrypts ciphertext into an EncryptedKey object using AES_CBC with the given key """ #not in used
    iv = data[:16]  # Extract IV from the beginning of the data
    ciphertext = data[16:]
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    return EncryptedKey.unpack(plaintext)

def decrypt_ticket(data: bytes, key: bytes) -> 'Ticket':
    """ Decrypts ciphertext into a Ticket object """ #not in used
    # Unpack the data
    server_version, client_id, server_id, creation_time, ticket_iv, encrypted_aes_key, encrypted_expiration_time = struct.unpack('<B16s16s8s16s32s8s', data[:81])
    
    # Decrypt the encrypted fields
    cipher = AES.new(key, AES.MODE_CBC, ticket_iv)
    aes_key = cipher.decrypt(encrypted_aes_key)
    expiration_time = cipher.decrypt(encrypted_expiration_time)
    
    # Create the Ticket object
    return Ticket(server_version, client_id, server_id, creation_time, ticket_iv, aes_key, expiration_time)

def decrypt_authenticator(data: bytes, client_key: bytes) -> Authenticator:
    """ Decrypts the ciphertext into an Authenticator object using AES_CBC with the given client_key """
    iv = data[:16]  # Extract IV from the beginning of the data
    ciphertext = data[16:]
    
    cipher = AES.new(client_key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    return Authenticator.unpack(plaintext)