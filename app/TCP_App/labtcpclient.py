import base64
import hashlib
import json
import socket
import struct

from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


class LabTcpClient:
    def __init__(self, ip, port, buffer):

        self.ip = ip
        self.port = port
        self.buffer = buffer
        self.server_address = (ip, port)
        self.data = None
        self.sock = None
        self.public_key_serv = None
        self.rsa_key = RSA.generate(1024, Random.new().read)
        self.public_key = self.rsa_key.publickey().exportKey()
        self.private_key = self.rsa_key.exportKey()
        self.private_key_imp = RSA.importKey(self.private_key)
        self.hash_public_key = hashlib.md5(self.public_key).hexdigest()
        self.create_socket()

    def create_socket(self):
        """Создаем подключение."""

        while not self.sock:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5)
            if self.connect_sock():
                self.public_key_serv = self.rsa_connect()
                print("Server conected create {}".format(self.server_address))

    def connect_sock(self):
        """Пытаемся подключится."""

        try:
            self.sock.connect(self.server_address)
            print("Connected to the server!")
            return True
        except socket.error:
            print("Unable to connect!")
            return False

    def rsa_connect(self):
        data = f'{self.public_key.decode("utf-8")}:{self.hash_public_key}'
        self.sock.send(bytes(data, encoding="utf-8"))

        # receive server public key,hash of public,eight byte and hash of eight byte
        fGet = self.sock.recv(self.buffer).decode("utf-8")
        split = fGet.split(":")
        tmpServerpublic = split[0]
        serverPublicHash = split[1]
        tmpHashObject = hashlib.md5(bytes(tmpServerpublic, encoding="utf-8"))
        tmpHash = tmpHashObject.hexdigest()

        if tmpHash != serverPublicHash:
            self.sock.close()
            self.sock = None
        else:
            Serverpublic = RSA.importKey(tmpServerpublic)
            return Serverpublic

    def send_data_server(self, data, is_text):
        """Отправка сообщения с помощью send."""
        # Prefix each message with a 8-byte length (network byte order)
        if not self.sock:
            self.reconnect()

        if is_text:
            data = bytes(json.dumps(data), encoding="utf-8")
            data = self.encrypt_with_public_key(data)

        try:
            data = struct.pack('>Q', len(data)) + data
            self.sock.sendall(data)
        except:
            # Новое создание сокета
            self.sock.close()
            self.sock = None

    def recv_data_server(self, is_text):
        """Возвращяем присланные данные"""
        # 8-byte
        payload_size = struct.calcsize(">Q")

        # Read message length and unpack it into an integer
        raw_msg_len = self.recv_all(payload_size)
        if not raw_msg_len:
            return None

        msg_len = struct.unpack('>Q', raw_msg_len)[0]

        # Read the message data
        data = self.recv_all(msg_len)
        try:
            if is_text:
                data = self.decrypt_with_private_key(data).decode("utf-8")
                try:
                    return json.loads(data)
                except ValueError:
                    return data

            return data
        except:
            # Новое создание сокета
            self.sock = None

    def recv_all(self, n):
        # Helper function to recv n bytes or return None if EOF is hit
        data = bytearray()

        while len(data) < n:
            packet = self.sock.recv(n - len(data))
            if not packet:
                return None

            data += packet

        return bytes(data)

    def encrypt_with_public_key(self, byte_message):
        """RSA Шифрование текста"""
        encryptor = PKCS1_OAEP.new(self.public_key_serv)
        encrypted_msg = encryptor.encrypt(byte_message)
        encoded_encrypted_msg = base64.b64encode(encrypted_msg)
        return encoded_encrypted_msg

    def decrypt_with_private_key(self, byte_message):
        """RSA Расшифровка текста"""
        decode_encrypted_msg = base64.b64decode(byte_message)
        private_key = PKCS1_OAEP.new(self.private_key_imp)
        decrypted_text = private_key.decrypt(decode_encrypted_msg)
        return decrypted_text

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


"""
BUFFER_SIZE = 4096
HOST = '127.0.1.1'
PORT = 9999


if __name__ == "__main__":
    CLT = LabTcpClient(HOST, PORT, BUFFER_SIZE)
"""
