import _thread as thread
import base64
import bcrypt
import hashlib
import json
import socket
import sys

from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from lazyme.string import color_print
from tinydb import Query, TinyDB

HOST = socket.gethostbyname(socket.gethostname())
PORT = 9999
MAX_CLIENTS = 99
BUFFER_SIZE = 4096
clients = {}
db = TinyDB('users.json')
socket_obj = socket.socket()

RSAkey = RSA.generate(1024, Random.new().read)
public_key = RSAkey.publickey().exportKey()
private_key = RSAkey.exportKey()
private_key_imp = RSA.importKey(private_key)

hash_public_key = hashlib.md5(public_key).hexdigest()


class User(object):
    def __init__(self, username, password):
        self.username = username
        self.password = password


class Logger(object):
    def __init__(self, filename="Default.log"):
        self.terminal = sys.stdout
        self.log = open(filename, "a")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        pass


sys.stdout = Logger("log_server.txt")


def on_new_client(client_socket, client_addr):
    try:
        client_authorize = False
        public_key_client = rsa_connect(client_socket)
        while True:
            if not client_authorize:
                data = recv_data_client(client_socket, private_key_imp)
                if data:
                    send_key = data['send_key']
                    print(client_addr)
                    print(send_key + " not auth")  # debug
                    if send_key == 'REGISTRATION':
                        username = data['username']
                        password = data['password']
                        if signup_user(username, password, public_key_client):
                            client_authorize = True
                    elif send_key == 'LOGIN':
                        username = data['username']
                        password = data['password']
                        if login_user(username, password, public_key_client):
                            client_authorize = True
                    else:
                        send_data_client(
                            client_socket, {'message': "Not Authorize", 'status': 'ERROR'}, public_key_client)
            else:
                try:
                    data = recv_data_client(client_socket, private_key_imp)
                    if data:
                        send_key = data['send_key']
                        print(send_key + " auth")  # debug
                        if send_key == "TEST":
                            print('authorize')
                    else:
                        client_socket.close()
                        print(
                            f"{clients[client_socket].username} has disconnected")
                except ConnectionResetError:
                    print(
                        f"Connection reset by {clients[client_socket].username}")
                    continue
    except Exception:
        client_socket.close()
        print(f"{client_addr} has disconnected")
        return True


def recv_data_client(client_socket, private_key_server):
    data = client_socket.recv(BUFFER_SIZE)
    try:
        data = decrypt_with_private_key(
            data, private_key_server).decode("utf-8")
        try:
            return json.loads(data)
        except ValueError:
            return data
    except ValueError:
        return data


def send_data_client(client_socket, data, public_key_client):

    data = bytes(json.dumps(data), encoding="utf-8")
    data = encrypt_with_public_key(data, public_key_client)

    client_socket.send(data)


def rsa_connect(client_socket):
    data = (client_socket.recv(BUFFER_SIZE)).decode(
        "utf-8").replace("\r\n", '')
    if data:
        split = data.split(":")
        tmpClientPublic = split[0]
        clientPublicHash = split[1]
        tmpHashObject = hashlib.md5(bytes(tmpClientPublic, encoding="utf-8"))
        tmpHash = tmpHashObject.hexdigest()

        if tmpHash == clientPublicHash:
            color_print(
                "\n[!] Anonymous client's public key and public key hash matched\n", color="blue")
            clientPublic = RSA.importKey(tmpClientPublic)

            data = f'{public_key.decode("utf-8")}:{hash_public_key}'
            client_socket.send(bytes(data, encoding="utf-8"))
            return clientPublic
        else:
            client_socket.close()
            print(f"{client_addr} has disconnected")


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


def signup_user(username, password, public_key_client):
    clients[client_socket] = User(username, password)
    query = Query()
    if not db.search(query.username == clients[client_socket].username):
        # Generate salt
        salt_pwd = bcrypt.gensalt()
        data = {
            "username": clients[client_socket].username,
            "password": bcrypt.hashpw(clients[client_socket].password.encode('utf-8'), salt_pwd).decode("utf-8"),
        }
        db.insert(data)
        send_data_client(
            client_socket, {'message': "Successfully!", 'status': 'SUCCESS'}, public_key_client)
        return True
    else:
        send_data_client(
            client_socket, {'message': "Username aloved!", 'status': 'ERROR'}, public_key_client)


def login_user(username, password, public_key_client):
    query = Query()
    data_user = db.get(query.username == username)
    if data_user:
        hash_pwd = data_user['password'].encode('utf-8')
        if bcrypt.checkpw(password.encode('utf-8'), hash_pwd):
            clients[client_socket] = User(
                username, password)
            return True
            send_data_client(
                client_socket, {'message': "Successfully!", 'status': 'SUCCESS'}, public_key_client)
        else:
            send_data_client(
                client_socket, {'message': "Invalid password!", 'status': 'ERROR'}, public_key_client)
    else:
        send_data_client(
            client_socket, {'message': "Invalid login!", 'status': 'ERROR'}, public_key_client)


if __name__ == "__main__":
    try:
        color_print("Server started!", color="yellow")
        color_print("Server adress: " + HOST + ":" + str(PORT), color="yellow")
        color_print("Waiting for clients...", color="yellow")
        socket_obj.bind((HOST, PORT))                   # Bind to the port
        # Now wait for client connection.
        socket_obj.listen(MAX_CLIENTS)
        while True:
            # Establish connection with client.
            client_socket, client_addr = socket_obj.accept()
            color_print(
                f'New incoming connection from {client_addr}', color="green")
            thread.start_new_thread(
                on_new_client, (client_socket, client_addr))
    except KeyboardInterrupt:
        socket_obj.close()
        color_print("Server stopped!", color="red")
