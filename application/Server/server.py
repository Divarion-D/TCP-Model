import _thread as thread
import hashlib
import socket
import sys

import bcrypt
import utils.common as common
from Crypto import Random
from Crypto.PublicKey import RSA
from lazyme.string import color_print
from utils.db import DB

HOST = socket.gethostbyname(socket.gethostname())
PORT = 9998
MAX_CLIENTS = 99
BUFFER_SIZE = 4096
clients = {}
socket_obj = socket.socket()

db = DB()
file = common.File()

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


sys.stdout = Logger("log_server.log")


def on_new_client(client_socket, client_addr, clients, private_key_imp):
    try:
        client_authorize = False
        public_key_client = rsa_connect(client_socket)
        while True:
            if not client_authorize:
                client_authorize = authorize_client(
                    client_socket, private_key_imp, public_key_client, clients
                )
            else:
                handle_authorized_client(
                    client_socket, private_key_imp, public_key_client, clients
                )
    except Exception:
        client_socket.close()
        print(f"{client_addr} has disconnected")
        return True


def authorize_client(client_socket, private_key_imp, public_key_client, clients):
    data = common.recv_data_client(client_socket, private_key_imp, True)
    if data:
        send_key = data.get("send_key")
        print(send_key + " not auth")  # debug
        if send_key == "SIGNUP":
            return handle_signup(data, public_key_client, clients, client_socket)
        elif send_key == "LOGIN":
            return handle_login(data, public_key_client, clients, client_socket)
        else:
            common.send_data_client(
                client_socket,
                {"message": "Not Authorize", "status": "ERROR"},
                public_key_client,
                True,
            )
    return False


def handle_signup(data, public_key_client, clients, client_socket):
    username = data.get("username")
    password = data.get("password")
    if signup_user(username, password, public_key_client):
        clients[client_socket] = {"username": username, "password": password}
        return True
    return False


def handle_login(data, public_key_client, clients, client_socket):
    username = data.get("username")
    password = data.get("password")
    if login_user(username, password, public_key_client):
        clients[client_socket] = {"username": username, "password": password}
        return True
    return False


def handle_authorized_client(
    client_socket, private_key_imp, public_key_client, clients
):
    try:
        data = common.recv_data_client(client_socket, private_key_imp, True)
        if data:
            handle_data(
                data, clients, client_socket, public_key_client, private_key_imp
            )
        else:
            disconnect_client(client_socket, clients)
    except ConnectionResetError:
        reset_connection(client_socket, clients)


def handle_data(data, clients, client_socket, public_key_client, private_key_imp):
    send_key = data.get("send_key")
    print(send_key + " auth")  # debug
    if send_key == "TEST":
        print("authorize")
    elif send_key == "FILE UPLOAD":
        file.file_upload(
            clients, client_socket, data, public_key_client, private_key_imp
        )


def disconnect_client(client_socket, clients):
    client_socket.close()
    print(f"{clients[client_socket]['username']} has disconnected")
    del clients[client_socket]


def reset_connection(client_socket, clients):
    print(f"Connection reset by {clients[client_socket]['username']}")
    del clients[client_socket]


def rsa_connect(client_socket):
    data = client_socket.recv(BUFFER_SIZE).decode("utf-8").replace("\r\n", "")
    if data:
        split_data = data.split(":")
        tmp_client_public = split_data[0]
        client_public_hash = split_data[1]
        tmp_hash_object = hashlib.md5(bytes(tmp_client_public, encoding="utf-8"))
        tmp_hash = tmp_hash_object.hexdigest()

        if tmp_hash == client_public_hash:
            color_print(
                "\n[!] Anonymous client's public key and public key hash matched\n",
                color="blue",
            )
            client_public = RSA.import_key(tmp_client_public)
            data = f"{public_key.decode('utf-8')}:{hash_public_key}"
            client_socket.send(bytes(data, encoding="utf-8"))
            return client_public
        else:
            client_socket.close()
            print(f"Client {client_addr} has disconnected")


def signup_user(username, password, public_key_client):
    print(User(username, password))
    clients[client_socket] = User(username, password)
    if db.check_username_exist(username):
        common.send_data_client(
            client_socket,
            {"message": "Username already exist", "status": "ERROR"},
            public_key_client,
            True,
        )
    else:
        db.add_user(username, password)  # add user to database
        common.send_data_client(
            client_socket,
            {"message": "Successfully!", "status": "OK"},
            public_key_client,
            True,
        )
        return True


def login_user(username, password, public_key_client):
    # get data from database for user
    data = db.get_user(username)
    if data:
        hash_pwd = data['password']  # get hash password from database
        if bcrypt.checkpw(password.encode("utf-8"), hash_pwd):  # check password
            common.send_data_client(
                client_socket,
                {"message": "Successfully!", "status": "OK"},
                public_key_client,
                True,
            )
            color_print("Successfully login!\n", color="green")
            return True
        else:
            common.send_data_client(
                client_socket,
                {"message": "Wrong password", "status": "ERROR"},
                public_key_client,
                True,
            )
            color_print("Wrong password\n", color="red")
    else:
        common.send_data_client(
            client_socket,
            {"message": "Username not exist", "status": "ERROR"},
            public_key_client,
            True,
        )
        color_print("Username not exist\n", color="red")


if __name__ == "__main__":
    try:
        color_print("Server started!", color="yellow")
        color_print("Server adress: " + HOST + ":" + str(PORT), color="yellow")
        color_print("Waiting for clients...", color="yellow")
        socket_obj.bind((HOST, PORT))  # Bind to the port
        # Now wait for client connection.
        socket_obj.listen(MAX_CLIENTS)
        while True:
            # Establish connection with client.
            client_socket, client_addr = socket_obj.accept()
            color_print(f"New incoming connection from {client_addr}", color="green")
            thread.start_new_thread(
                on_new_client, (client_socket, client_addr, clients, private_key_imp)
            )
    except KeyboardInterrupt:
        socket_obj.close()
        color_print("Server stopped!", color="red")
