from hashlib import sha256
import hashlib
from Crypto.Cipher import AES 
# Advanced Encryption Standard (AES) algorithm in EAX mode

from pbkdf2 import PBKDF2
# Password-Based key derivation function or PBKDF2 algorithm is used to for cryptographic functions. 

from base64 import b64encode, b64decode 
# Base64 module is imported to encode and decode binary data in base64 format.

salt = b'1101000000100010'
#Salt is defined as a binary string, which will be used to derive secure and unique hashed passwords.

def query_master_pwd(master_password): 

    master_password_hash = "fc613b4dfd6736a7bd268c8a0e74ed0d1c04a959f59dd74ef2874983fd443fc9"
    # A hashed master password is saved in master_password_hash function

    compile_factor_together = hashlib.sha256(master_password).hexdigest()
    # Takes a master_password argument and hashing it using SHA-256.

    if compile_factor_together == master_password_hash: 
        return True  
    # Compares the resulting hash with the pre-defined master_password_hash. 
    # If the two match, returns True, indicating that the master_password is correct.



def encrypt_password(password_to_encrypt, master_password_hash): 
#The encrypt_password() function takes a password_to_encrypt and a master_password_hash argument.
    
    key = PBKDF2(str(master_password_hash), salt).read(32)
    # Takes the master_password_hash and salt to perform iterative hash functions. 
    # Gives a unique key of length 32 bytes (256 bits) using the PBKDF2 algorithm. 

    data_convert = str.encode(password_to_encrypt)
    # Encoded in bytes as the encryption algorithm expects bytes as input.

    cipher = AES.new(key, AES.MODE_EAX) 
    # The derived key, AES encryption module is used to derive a AES cipher
    # Password is then encrypted using AES in EAX mode with the cipher key.
    
    nonce = cipher.nonce
    # The cipher generates a random nonce (a "number used once") that is used in the encryption.

    ciphertext, tag = cipher.encrypt_and_digest(data_convert)
    # The password is then encrypted using the encrypt_and_digest() method of the cipher object.
    # tag that is used for authentication.

    add_nonce = ciphertext + nonce
    encoded_ciphertext = b64encode(add_nonce).decode()
    # Resulting ciphertext is combined with a nonce and encoded in base64 for ease of storage.

    return encoded_ciphertext

def decrypt_password(password_to_decrypt, master_password_hash): 
    
    if len(password_to_decrypt) % 4:
     
     password_to_decrypt += '=' * (4 - len(password_to_decrypt) % 4)

    convert = b64decode(password_to_decrypt)
    # The password_to_decrypt is decoded from base64 format.

    key = PBKDF2(str(master_password_hash), salt).read(32)
    # Takes the master_password_hash and salt to perform iterative hash functions 
    # Gives a unique key of length 32 bytes (256 bits) using the PBKDF2 algorithm. (same as above)

    nonce = convert[-16:]
    # Split into ciphertext and nonce
    
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    # Ciphertext is decrypted using AES in EAX mode with the derived key and nonce.

    plaintext = cipher.decrypt(convert[:-16]) 

    return plaintext