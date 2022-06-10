import json
import select
import socket
import sys
import threading

from tinydb import Query, TinyDB

HOST = socket.gethostbyname(socket.gethostname())
PORT = 9999
MAX_CLIENTS = 99
BUFFER_SIZE = 4096
sockets_list = []
clients = {}


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
db = TinyDB('users.json')


def run_server():
    while True:
        exception_sockets = select.select(sockets_list, [], [])
        for notified_socket in exception_sockets:
            if notified_socket == server_socket:
                client_socket, client_address = server_socket.accept()
                print(f"New incoming connection from {client_address[0]}")
                sockets_list.append(client_socket)
                client_aithorize = False
            if not client_aithorize:
                data = recv_data_client(client_socket)
                if data:
                    send_key = data['send_key']
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
                            client_aithorize = True
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
                            client_aithorize = True
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
                    data = recv_data_client(notified_socket)
                    if data:
                        send_key = data['send_key']
                        print(send_key + " auth")  # debug
                        if send_key == "TEST":
                            print('authorize')
                    else:
                        remove_socket(notified_socket)
                        print(
                            f"{clients[notified_socket].username} has disconnected")
                except ConnectionResetError:
                    print(
                        f"Connection reset by {clients[client_socket].username}")
                    continue


def recv_data_client(client_socket):
    data = (client_socket.recv(BUFFER_SIZE)).decode("utf-8")
    try:
        return json.loads(data)
    except ValueError:
        return data


def send_data_client(client_socket, data):
    data = json.dumps(data)
    client_socket.send(bytes(data, encoding="utf-8"))


def send_to_client(message, client_socket, server_socket):
    for client in sockets_list[1:]:
        if client == client_socket and client != server_socket:
            try:
                client_socket.send(message.encode())
            except:
                remove_socket(client)


def remove_socket(client_socket):
    if client_socket in sockets_list:
        sockets_list.remove(client_socket)
        client_socket.close()


if __name__ == "__main__":
    try:
        print("Running server script..")
        print("Starting server on port 9999!")
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(MAX_CLIENTS)
        sockets_list.append(server_socket)
        print(f"Server started on {HOST} : {PORT}")
        print("Waiting for incoming connections..")
        threading.Thread(target=run_server())
    except KeyboardInterrupt:
        server_socket.close()
        print("\nServer stopped!")
