import json
import socket

BUFFER_SIZE = 4096
HOST = '127.0.1.1'
PORT = 9999


class LabTcpClient:
    def __init__(self, ip, port, buffer):

        self.ip = ip
        self.port = port
        self.buffer = buffer
        self.server_address = (ip, port)
        self.data = None
        self.sock = None
        self.create_socket()

    def create_socket(self):
        """Создаем подключение."""

        while not self.sock:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5)
            self.connect_sock()
            print("Server conected create {}".format(self.server_address))

    def connect_sock(self):
        """Пытаемся подключится."""

        try:
            self.sock.connect(self.server_address)
            print("Connected to the server!")
            return 1
        except socket.error:
            print("Unable to connect!")
            return None

    def send_data_server(self, data):
        """Отправка сообщения с помощью send."""
        # Если нет подключения пытаемся подключится заново
        if not self.sock:
            self.reconnect()

        data = json.dumps(data)

        try:
            self.sock.send(bytes(data, encoding="utf-8"))
        except:
            print("Send: {}".format(data))
            # Новое создание сокета
            self.sock.close()
            self.sock = None

    def recv_data_server(self):
        """Возвращяем присланные данные"""
        return self.sock.recv(self.buffer).decode("utf-8")

    def reconnect(self):
        """Переподключится."""

        self.sock = None
        self.create_socket()

    def close_sock(self):
        """Закрыть соеденение"""

        try:
            self.sock.close()
        except:
            print("Клиентский сокет уже закрыт")

        self.sock = None

    def listen(self):
        """Возвращает полученные необработанные данные."""

        raw_data = None
        raw_data = self.sock.recv()
        return raw_data


if __name__ == "__main__":
    try:
        clt = LabTcpClient(HOST, PORT, BUFFER_SIZE)
        while True:
            append = input("Command: ")
            if append == '/reg':
                username = input("Username: ")
                password = input("Password: ")
                reg_data = {'username': username,
                            'password': password, 'send_key': 'REGISTRATION'}
                clt.send_data_server(reg_data)
                print(clt.recv_data_server())
            elif append == '/auth':
                username = input("Username: ")
                password = input("Password: ")
                reg_data = {'username': username,
                            'password': password, 'send_key': 'LOGIN'}
                clt.send_data_server(reg_data)
                print(clt.recv_data_server())
            else:
                reg_data = {'massage': append, 'send_key': 'TEST'}
                clt.send_data_server(reg_data)
    except KeyboardInterrupt:
        print("\nClient Disconnected!")
