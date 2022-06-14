import json
import socket

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
        data = self.sock.recv(self.buffer).decode("utf-8")
        data = json.loads(data)
        return data

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