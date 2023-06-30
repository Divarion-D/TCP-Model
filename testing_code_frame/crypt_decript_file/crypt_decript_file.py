import base64
from operator import index
from tkinter import W
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

file = 'index.jpeg'

def write_key():
    key = Fernet.generate_key()
    with open("password.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("password.key", "rb").read()

def encrypt(filename):
    password = input("Enter password to register:").encode()
    write_key()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=32,
        salt=load_key(),
        iterations=100000,
        backend=default_backend(),
    )
    encryption_key = (base64.urlsafe_b64encode(kdf.derive(password)))
    encryption_key_fernet = Fernet(encryption_key)
    with open(filename, "rb") as file:
        # read all file data
        file_data = file.read()
    encrypted_data = encryption_key_fernet.encrypt(file_data)
    with open(filename, "wb") as file:
        file.write(encrypted_data)

    decrypt(filename)

def decrypt(filename):
    password = input("Enter password to login:").encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=32,
        salt=load_key(),
        iterations=100000,
        backend=default_backend(),
    )
    decryption_key = (base64.urlsafe_b64encode(kdf.derive(password)))
    decryption_key_fernet = Fernet(decryption_key)

    with open(filename, "rb") as file:
        # read the encrypted data
        encrypted_data = file.read()
    # decrypt data
    decrypted_data = decryption_key_fernet.decrypt(encrypted_data)
    # write the original file
    with open(filename, "wb") as file:
        file.write(decrypted_data)

encrypt(file)        