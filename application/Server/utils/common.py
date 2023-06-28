import base64
import json
import os
import random
import string
import struct
import sys

from Crypto.Cipher import PKCS1_OAEP

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # Добавляем путь до папки с модулями


def send_data_client(client_socket, data, public_key_client, is_text):
    # Prefix each message with a 8-byte length (network byte order)
    if is_text:
        data = bytes(json.dumps(data), encoding="utf-8")

    data = encrypt_with_public_key(data, public_key_client)

    data = struct.pack('>Q', len(data)) + data
    client_socket.sendall(data)


def recv_data_client(client_socket, private_key_server, is_text):
    # 8-byte
    payload_size = struct.calcsize(">Q")

    # Read message length and unpack it into an integer
    raw_msg_len = receive_all(client_socket, payload_size)
    if not raw_msg_len:
        return None

    msg_len = struct.unpack('>Q', raw_msg_len)[0]

    # Read the message data
    data = receive_all(client_socket, msg_len)
    if is_text:
        data = decrypt_with_private_key(data, private_key_server)
        try:
            return json.loads(data)
        except ValueError:
            return data

    return data


def receive_all(client_socket, n):
    # Helper function to recv n bytes or return None if EOF is hit
    data = bytearray()

    while len(data) < n:
        packet = client_socket.recv(n - len(data))
        if not packet:
            return None

        data += packet

    return bytes(data)


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


class File:
    def __init__(self):
        pass

    def get_random_string(self, length):
        '''
        Generate a random string of fixed length
        '''
        result_str = ''.join(random.choice(string.ascii_letters)
                             for i in range(length))
        return result_str

    def file_upload(self, clients, client_socket, recv_data, public_key_client, private_key_imp):
        '''
        Client upload file
        '''
        file_name = recv_data['file_name']  # get file name
        send_data_client(
            client_socket, {'status': 'OK'}, public_key_client, True)  # send status OK

        path = "file_tmp_upload/" + clients[client_socket]['username'] + "/"  # path to file

        if not os.path.exists(path):  # if folder not exist
            os.makedirs(path)  # create folder

        data = recv_data_client(client_socket, private_key_imp, False)  # get file data
        with open(os.path.join(path, file_name), 'wb') as f:
            f.write(data)  # write file
        return True
