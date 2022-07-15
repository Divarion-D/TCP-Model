import struct
import json
import base64
import os
import sys
import sqlite3
import bcrypt



sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from file_hosting.anonfile import AnonFile
from Crypto.Cipher import PKCS1_OAEP


class DB:
    def __init__(self):
        self.db = sqlite3.connect('database.db', check_same_thread=False)
        self.cur = self.db.cursor()

        self.db.execute('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS users_file(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, file_name TEXT, file_host TEXT, file_url TEXT)''')
        self.db.commit()

    def check_username_exist(self, username):
        self.cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        return self.cur.fetchone() is not None

    def add_user(self, username, password):
        hash_pwd = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()) # hash password
        self.cur.execute("INSERT INTO users(username, password) VALUES(?, ?)", (username, hash_pwd))
        self.db.commit()

    def get_user(self, username):
        self.cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        return self.cur.fetchone()


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
        packet = client_socket.recv(n - len(data))
        if not packet:
            return None

        data += packet

    return bytes(data)


def encrypt_with_public_key(byte_message, public_key):
    """RSA Шифрование текста"""
    encryptor = PKCS1_OAEP.new(public_key)
    encrypted_msg = encryptor.encrypt(byte_message)
    encoded_encrypted_msg = base64.b64encode(encrypted_msg)
    return encoded_encrypted_msg


def decrypt_with_private_key(byte_message, private_key):
    """RSA Расшифровка текста"""
    decode_encrypted_msg = base64.b64decode(byte_message)
    private_key = PKCS1_OAEP.new(private_key)
    decrypted_text = private_key.decrypt(decode_encrypted_msg)
    return decrypted_text


def file_upload(clients, client_socket, recv_data, public_key_client, private_key_imp):
    file_name = recv_data['file_name'] # получаем название файла
    send_data_client(client_socket, {'status': 'OK'}, public_key_client, True)

    path = "file_tmp/" + clients[client_socket]['username'] + "/"

    if not os.path.exists(path):
        os.makedirs(path)

    data = recv_data_client(client_socket, private_key_imp, False)
    with open(os.path.join(path, file_name), 'wb') as f:
        f.write(data)
    return True

def file_upload_filehosting():
    # get list folders name from file_temp
    path = "file_tmp/"
    folders = os.listdir(path)
    for folder in folders:
        # get list files name from folder
        path_folder = path + folder
        files = os.listdir(path_folder)
        for file in files:
            # upload file to anonfile
            file_path = path_folder + "/" + file
            anonfile = AnonFile()
            json = anonfile.UploadFile(file_path)
            print(json)