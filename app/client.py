import socket
import sys
import json
import select

BUFFER_SIZE = 4096
HOST = '127.0.1.1'
PORT = 9999

def client():
    client_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_connection.settimeout(5)
    try:
        client_connection.connect((HOST, PORT))
    except socket.error:
        print("Unable to connect!")
        sys.exit(0)
    print("Connected to the server!")
    sys.stdout.write("> ")
    sys.stdout.flush()
    while True:
        sockets_list = [sys.stdin, client_connection]
        r, w, e = select.select(sockets_list, [], [])
        for notified_socket in r:
            if notified_socket == client_connection:
                data = client_connection.recv(BUFFER_SIZE).decode()
                if data == "GETADMINPASS":
                    tmp_pass = "123"
                    client_connection.send(tmp_pass.encode())
                    sys.stdout.write("> ")
                    sys.stdout.flush()
                elif data:
                    sys.stdout.write(data)
                    sys.stdout.write("> ")
                    sys.stdout.flush()
                else:
                    print("You have been disconnected from the  server!")
                    sys.exit(0)
            else:
                append = sys.stdin.readline()
                if append == '/reg\n':
                    username = input("Username: ")
                    password = input("Password: ")
                    reg_data = {'username': username, 'password': password, 'send_key': 'REGISTRATION'}
                    send_data_server(client_connection, reg_data)
                    print(client_connection.recv(BUFFER_SIZE).decode())
                    sys.stdout.write("> ")
                    sys.stdout.flush()
                elif append == '/auth\n':
                    username = input("Username: ")
                    password = input("Password: ")
                    reg_data = {'username': username, 'password': password, 'send_key': 'LOGIN'}
                    send_data_server(client_connection, reg_data)
                    print(client_connection.recv(BUFFER_SIZE).decode())
                    sys.stdout.write("> ")
                    sys.stdout.flush()
                else:
                    reg_data = {'massage': append, 'send_key': 'TEST'}
                    send_data_server(client_connection, reg_data)
                    sys.stdout.write("> ")
                    sys.stdout.flush()

def send_data_server(client_connection, data):
    data = json.dumps(data)
    #(len(bytes(data,encoding="utf-8"))) #длина сообщения
    client_connection.send(bytes(data,encoding="utf-8"))


if __name__ == "__main__":
    try:
        client()
    except KeyboardInterrupt:
        print("\nClient Disconnected!")