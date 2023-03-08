import string
# String module is used to generate all upper, lower case letters and (0-9) digit characters.

import secrets
# This module is used to generate cryptographically strong random numbers for data such as passwords.
# Secrets module is designed specifically for cryptographic purposes to generate random numbers.


def password_gen(password_length):
# The function password_gen() that generates a random password of a specified length.
# The password_length argument is an integer specifies the length of the password to be generated
    
    characters = string.ascii_letters + string.digits
    # A string called characters contains all upper, lower case letters and (0-9) digits. 

    secure_password = ''.join(secrets.choice(characters) for i in range(password_length))
    # The secrets.choice() function is then used to randomly select a character from the characters.
    # Each selected character is concatenated to the secure_password string using the .join() method.

    return secure_password