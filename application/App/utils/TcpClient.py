import base64
import hashlib
import json
import logging
import socket
import struct

from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

logging.basicConfig(filename='log_client.log')


class TcpClient:
    def __init__(self, ip: str, port: int, buffer_size: int):
        self.ip = ip
        self.port = port
        self.buffer_size = buffer_size
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
        """Create a connection."""
        while not self.sock:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5)
            if self.connect_sock():
                self.public_key_serv = self.rsa_connect()
                print("Server connected: create {}".format(self.server_address))

    def connect_sock(self):
        """
        Attempts to connect to the server.
        Returns True if successful, False otherwise.
        """
        try:
            self.sock.connect(self.server_address)
            logging.info("Connected to the server!")
            return True
        except socket.error:
            logging.error("Unable to connect!")
            return False

    def rsa_connect(self):
        public_key_str = self.public_key.decode("utf-8")
        data = f"{public_key_str}:{self.hash_public_key}"
        self.sock.send(bytes(data, encoding="utf-8"))
        # receive server public key, hash of public, eight bytes, and hash of eight bytes
        response = self.sock.recv(self.buffer_size).decode("utf-8")
        server_public_key_str, server_public_key_hash = response.split(":")
        tmp_hash = hashlib.md5(bytes(server_public_key_str, encoding="utf-8")).hexdigest()
        if tmp_hash != server_public_key_hash:
            self.sock.close()
            self.sock = None
            return None
        else:
            server_public_key = RSA.importKey(server_public_key_str)
            return server_public_key

    def send_data_server(self, data, is_text):
        """Send message using send method."""
        # Prefix each message with an 8-byte length (network byte order)
        if not self.sock:
            self.reconnect()
        if is_text:
            data = bytes(json.dumps(data), encoding="utf-8")
            data = self.encrypt_with_public_key(data)
        try:
            data_len = len(data)
            data_with_len = struct.pack('>Q', data_len) + data
            self.sock.sendall(data_with_len)
        except Exception as e:
            # Reconnect and try again if there was an error
            logging.error("Error send data: %s", e)
            self.sock.close()
            self.sock = None
            self.reconnect()

    def recv_data_server(self, is_text_data):
        """
        Returns the received data.
        """
        # 8-byte
        payload_bytes = struct.calcsize(">Q")
        # Read message length and unpack it into an integer
        raw_msg_len = self.receive_all(payload_bytes)
        if not raw_msg_len:
            return None
        message_length = struct.unpack('>Q', raw_msg_len)[0]
        # Read the message data
        data = self.receive_all(message_length)
        try:
            if is_text_data:
                data = self.decrypt_with_private_key(data).decode("utf-8")
                try:
                    return json.loads(data)
                except json.JSONDecodeError:
                    return data
            else:
                return data
        except Exception:
            # Creating a new socket
            self.sock = None

    def receive_all(self, n):
        # Helper function to receive n bytes or return None if EOF is hit
        received_data = bytearray()
        while len(received_data) < n:
            received_packet = self.sock.recv(n - len(received_data))
            if not received_packet:
                return None
            received_data += received_packet
        return bytes(received_data)

    def encrypt_with_public_key(self, byte_message):
        """RSA Шифрование текста"""
        print(byte_message)
        encryptor = PKCS1_OAEP.new(self.public_key_serv)
        encrypted_msg = encryptor.encrypt(byte_message)
        encoded_encrypted_msg = base64.b64encode(encrypted_msg)
        return encoded_encrypted_msg

    def decrypt_with_private_key(self, byte_message):
        """RSA Расшифровка текста"""
        decoded_encrypted_message = base64.b64decode(byte_message)
        private_key = PKCS1_OAEP.new(self.private_key_imp)
        decrypted_text = private_key.decrypt(decoded_encrypted_message)
        return decrypted_text

    def reconnect(self):
        """
        Reconnects the socket.
        """
        self.sock = None
        self.create_socket()

    def close_socket(self):
        """
        Close the connection.
        """
        try:
            self.sock.close()
        except OSError as e:
            logging.error("Error while closing client socket: %s", format(e))
        self.sock = None
        return None

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
    CLT = TcpClient(HOST, PORT, BUFFER_SIZE)
"""
