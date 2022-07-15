import _thread as thread

import hashlib
import socket
import sys

from common import *

from Crypto import Random
from Crypto.PublicKey import RSA
from lazyme.string import color_print

HOST = socket.gethostbyname(socket.gethostname())
PORT = 9999
MAX_CLIENTS = 99
BUFFER_SIZE = 4096
clients = {}
socket_obj = socket.socket()

db = DB()

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
        client_authorize = False
        public_key_client = rsa_connect(client_socket)
        while True:
            if not client_authorize:
                data = recv_data_client(client_socket, private_key_imp, True)
                if data:
                    send_key = data['send_key']
                    print(client_addr)
                    print(send_key + " not auth")  # debug
                    if send_key == 'SIGNUP':
                        username = data['username']
                        password = data['password']
                        if signup_user(username, password, public_key_client):
                            clients[client_socket] = {'username': username, 'password': password}
                            client_authorize = True
                    elif send_key == 'LOGIN':
                        username = data['username']
                        password = data['password']
                        if login_user(username, password, public_key_client):
                            clients[client_socket] = {'username': username, 'password': password}
                            client_authorize = True
                    else:
                        send_data_client(
                            client_socket, {'message': "Not Authorize", 'status': 'ERROR'}, public_key_client, True)
            else:
                try:
                    data = recv_data_client(client_socket, private_key_imp, True)
                    if data:
                        send_key = data['send_key']
                        print(send_key + " auth")  # debug
                        if send_key == "TEST":
                            print('authorize')
                        elif send_key == "FILE UPLOAD":
                            file_upload(clients, client_socket, data, public_key_client, private_key_imp)
                    else:
                        client_socket.close()
                        print(
                            f"{clients[client_socket]['username']} has disconnected")
                        del clients[client_socket]
                except ConnectionResetError:
                    print(
                        f"Connection reset by {clients[client_socket]['username']}")
                    del clients[client_socket]
                    continue




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


def signup_user(username, password, public_key_client):
    clients[client_socket] = User(username, password)
    if db.check_username_exist:
        send_data_client(client_socket, {'message': "Username already exist", 'status': 'ERROR'}, public_key_client, True)
    else:
        db.add_user(username, password) # add user to database
        send_data_client(client_socket, {'message': "Successfully!", 'status': 'OK'}, public_key_client, True)
        return True


def login_user(username, password, public_key_client):
    # get data from database for user
    data = db.get_user(username)
    if data:
        hash_pwd = data[2] # get hash password from database
        if bcrypt.checkpw(password.encode('utf-8'), hash_pwd): # check password
            send_data_client(client_socket, {'message': "Successfully!", 'status': 'OK'}, public_key_client, True)
            return True
        else:
            send_data_client(client_socket, {'message': "Wrong password", 'status': 'ERROR'}, public_key_client, True)
    else:
        send_data_client(client_socket, {'message': "Username not exist", 'status': 'ERROR'}, public_key_client, True)
    

if __name__ == "__main__":
    try:
        file_upload_filehosting()
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
