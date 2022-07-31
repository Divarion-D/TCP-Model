import base64
import json
import os
import random
import sqlite3
import string
import struct
import sys

import bcrypt
from Crypto.Cipher import PKCS1_OAEP

from file_hosting.anonfile import AnonFile 

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) # Добавляем путь до папки с модулями


class DB:
    def __init__(self):
        self.db = sqlite3.connect('database.db', check_same_thread=False)
        self.cur = self.db.cursor()

        self.db.execute(
            '''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)''')
        # remove table users_file
        self.db.execute('''DROP TABLE IF EXISTS users_file''')
        self.db.execute(
            '''CREATE TABLE IF NOT EXISTS users_file(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, file_name TEXT, file_host TEXT, file_id TEXT, file_key TEXT)''')
        self.db.commit()

    def check_username_exist(self, username):
        self.cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        return self.cur.fetchone() is not None

    def add_user(self, username, password):
        hash_pwd = bcrypt.hashpw(password.encode(
            'utf-8'), bcrypt.gensalt())  # hash password
        self.cur.execute(
            "INSERT INTO users(username, password) VALUES(?, ?)", (username, hash_pwd))
        self.db.commit()

    def get_user(self, username):
        self.cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        return self.cur.fetchone()

    def add_file(self, username, file_name, file_host, file_id, file_key):
        self.cur.execute("INSERT INTO users_file(username, file_name, file_host, file_id, file_key) VALUES(?, ?, ?, ?, ?)",
                         (username, file_name, file_host, file_id, file_key))
        self.db.commit()


def send_data_client(client_socket, data, public_key_client, is_text):
    # Prefix each message with a 8-byte length (network byte order)
    if is_text:
        data = bytes(json.dumps(data), encoding="utf-8")

    data = encrypt_with_public_key(data, public_key_client)

    data = struct.pack('>Q', len(data)) + data
    client_socket.sendall(data)


def recv_data_client(client_socket, private_key_server, is_text):
    # 8-byte
    payload_size = struct.calcsize(">Q")

    # Read message length and unpack it into an integer
    raw_msg_len = recv_all(client_socket, payload_size)
    if not raw_msg_len:
        return None

    msg_len = struct.unpack('>Q', raw_msg_len)[0]

    # Read the message data
    data = recv_all(client_socket, msg_len)
    if is_text:
        data = decrypt_with_private_key(data, private_key_server)
        try:
            return json.loads(data)
        except ValueError:
            return data

    return data


def recv_all(client_socket, n):
    # Helper function to recv n bytes or return None if EOF is hit
    data = bytearray()

    while len(data) < n:
        if packet := client_socket.recv(n - len(data)):
            data += packet

        else:
            return None

    return bytes(data)


def encrypt_with_public_key(byte_message, public_key):
    """RSA Шифрование текста"""
    encryptor = PKCS1_OAEP.new(public_key)
    encrypted_msg = encryptor.encrypt(byte_message)
    return base64.b64encode(encrypted_msg)


def decrypt_with_private_key(byte_message, private_key):
    """RSA Расшифровка текста"""
    decode_encrypted_msg = base64.b64decode(byte_message)
    private_key = PKCS1_OAEP.new(private_key)
    return private_key.decrypt(decode_encrypted_msg)


class File:
    def __init__(self):
        self.db_class = DB()
        self.anon_file = AnonFile()

    def get_random_string(self, length):
        '''
        Generate a random string of fixed length
        '''
        return ''.join(random.choice(string.ascii_letters) for _ in range(length))

    def file_upload(self, clients, client_socket, recv_data, public_key_client, private_key_imp):
        '''
        Client upload file
        '''
        file_name = recv_data['file_name']  # get file name
        send_data_client(
            client_socket, {'status': 'OK'}, public_key_client, True) # send status OK

        path = "file_tmp_upload/" + clients[client_socket]['username'] + "/" # path to file

        if not os.path.exists(path): # if folder not exist
            os.makedirs(path) # create folder

        data = recv_data_client(client_socket, private_key_imp, False) # get file data
        with open(os.path.join(path, file_name), 'wb') as f:
            f.write(data) # write file
        return True

    def file_upload_filehosting(self):
        '''
        Function loop for upload file to filehosting 
        '''
        path = "file_tmp_upload/" # path to file
        folders = os.listdir(path) # get list of folders
        for folder in folders: 
            path_folder = path + folder # path to folder
            files = os.listdir(path_folder) # get list of files
            for file in files: 
                hash_key = self.get_random_string(16) # generate hash key
                file_path = f"{path_folder}/{file}"
                file_id = self.anon_file.UploadFile(file_path) # upload file
                self.db_class.add_file( 
                    folder, file, 'anonfile', file_id, str(hash_key)) # add file to DB
