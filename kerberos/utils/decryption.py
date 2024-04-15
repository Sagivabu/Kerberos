from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib

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

def decrypt_with_aes_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-CBC with the given key and IV

    Args:
        key (bytes): usually the 'client_key'
        iv (bytes): usually the 'decrypted_key_iv'
        ciphertext (bytes): the text to decrypt

    Returns:
        bytes: plain_text
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

def client_decrypt_encrypted_key(encrypted_key_iv: bytes, encrypted_nonce: bytes, encrypted_server_key: bytes, password_hash: bytes, salt: bytes) -> tuple:
    """
    Function that helps the client to decrypt 'EncryptedKey' object, which consist 'encrypted_nonce' and 'encrypted_server_key' (AES_key)

    Args:
        encrypted_key_iv (bytes): consist the IV to decrypt the 'Nonce' and 'AES_key', this IV is encrypted with the 'client_key'
        encrypted_nonce (bytes): 'Nonce' to verify the response from Auth_server
        encrypted_server_key (bytes): AES_key is a shared key between the client and server 
        password_hash (bytes): Client's password_hash to create the 'client_key'
        salt (bytes): client's own salt

    Returns:
        tuple (bytes, bytes): (decrypted_nonce, decrypted_server_key)
    """
    # Derive client key from password hash
    client_key = derive_client_key(password_hash, salt)
    
    # Decrypt the Encrypted Key IV
    decrypted_key_iv = decrypt_with_aes_cbc(client_key, encrypted_key_iv[:16], encrypted_key_iv[16:])
    
    # Decrypt the Encrypted Nonce and AES Key using the decrypted IV and client key
    decrypted_nonce = decrypt_with_aes_cbc(client_key, decrypted_key_iv, encrypted_nonce)
    decrypted_server_key = decrypt_with_aes_cbc(client_key, decrypted_key_iv, encrypted_server_key)
    
    return decrypted_nonce, decrypted_server_key