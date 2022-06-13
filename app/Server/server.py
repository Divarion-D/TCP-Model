import _thread as thread
import json
import socket
import sys

from tinydb import Query, TinyDB

HOST = socket.gethostbyname(socket.gethostname())
PORT = 9999
MAX_CLIENTS = 99
BUFFER_SIZE = 4096
clients = {}
db = TinyDB('users.json')
socket_obj = socket.socket()


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
        while True:
            if not client_authorize:
                data = recv_data_client(client_socket)
                if data:
                    send_key = data['send_key']
                    print(client_addr)
                    print(send_key + " not auth")  # debug
                    if send_key == 'REGISTRATION':
                        username = data['username']
                        password = data['password']
                        clients[client_socket] = User(username, password)
                        query = Query()
                        if not db.search(query.username == clients[client_socket].username):
                            data = {
                                "username": clients[client_socket].username,
                                "password": clients[client_socket].password,
                            }
                            db.insert(data)
                            client_authorize = True
                            send_data_client(
                                client_socket, {'message': "Successfully!", 'status': 'SUCCESS'})
                        else:
                            send_data_client(
                                client_socket, {'message': "Username aloved!", 'status': 'ERROR'})
                    elif send_key == 'LOGIN':
                        username = data['username']
                        password = data['password']
                        query = Query()
                        if db.search(query.username == username and query.password == password):
                            clients[client_socket] = User(username, password)
                            client_authorize = True
                            send_data_client(
                                client_socket, {'message': "Successfully!", 'status': 'SUCCESS'})
                        else:
                            send_data_client(
                                client_socket, {'message': "Invalid password or login!", 'status': 'ERROR'})
                    else:
                        send_data_client(
                            client_socket, {'message': "Not Authorize", 'status': 'ERROR'})
            else:
                try:
                    data = recv_data_client(client_socket)
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
                    print(f"Connection reset by {clients[client_socket].username}")
                    continue
    except Exception:
            client_socket.close()
            print(f"{client_addr} has disconnected")
            return True

def recv_data_client(client_socket):
    data = (client_socket.recv(BUFFER_SIZE)).decode("utf-8")
    try:
        return json.loads(data)
    except ValueError:
        return data


def send_data_client(client_socket, data):
    data = json.dumps(data)
    client_socket.send(bytes(data, encoding="utf-8"))


if __name__ == "__main__":
    try:
        print('Server started!')
        print('Waiting for clients...')
        socket_obj.bind((HOST, PORT))                   # Bind to the port
        # Now wait for client connection.
        socket_obj.listen(MAX_CLIENTS)
        while True:
            # Establish connection with client.
            client_socket, client_addr = socket_obj.accept()
            print('New incoming connection from', client_addr)
            thread.start_new_thread(
                on_new_client, (client_socket, client_addr))
    except KeyboardInterrupt:
        socket_obj.close()
        print("\nServer stopped!")
