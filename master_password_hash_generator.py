import hashlib
from hashlib import sha256 
# The hashlib module provides access to the SHA-256 cryptographic hash function.
# The SHA-256 algorithm is a cryptographic hash function that takes an input 
# Generates a fixed-size output of 256 bits (32 bytes) in form of a string.

def master_password_gen(): # Define a function to generate a hashed master password

    master_password = input("Enter your password: ").encode()
    # The user is prompted to enter their password using the input() function.
    # The entered password is converted from a string to a bytes object using the encode() method.    
    
    compile_factor_together = hashlib.sha256(master_password).hexdigest()
    # The hexdigest() method is called on the hashed object to convert it to hexadecimal digits.

    print("Master Password: " + str(compile_factor_together))

master_password_gen()

 

