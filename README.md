# Encwork
<!-- Shields.io Badges -->
[![Release](https://img.shields.io/github/v/release/Divarion-D/TCP-Model?style=flat-square)](https://github.com/Divarion-D/TCP-Model/releases)
[![License](https://img.shields.io/github/license/Divarion-D/TCP-Model?style=flat-square)](https://github.com/Divarion-D/TCP-Model/blob/master/LICENSE)
[![Python](https://img.shields.io/badge/python-3.6%20%7C%203.7%20%7C%203.8-blue?style=flat-square)](https://www.python.org/downloads/)
<!-- End of Badges -->
RSA-encrypted networking library.

## What is it for?
The TCP Model is designed as a secure network system that will generate new keys for each session. It can be used for CLIs or command line tools, shared networks that need to be encrypted, or one-time chats.

## How is it secured?
Encwork uses 4096-bit RSA keys (size changable, 4096 recommended) for every message other than for the public key exchange, which cannot be encrypted and does not need to be.  
This should not be a problem, as no computer can get the private key from the public key, and the keys are recreated for every new session.

## How does it work?
### Server-Based
There will be one machine running a server, and multiple clients can connect to it. The server talks to each client individually, but Encwork provides enough freedom that you could set up a system that allows users to talk to each other. The server will store all client's public keys & sockets in a dictionary, so all clients still have different keys that don't cross paths.

## Requirements
**Python v3.6+**  
If you don't already have it, download it [here](https://www.python.org/downloads/).  
**cryptography>=2.8**  
Download it using `pip install "cryptography>=2.8"`, or download the wheel [here](https://pypi.org/project/cryptography/2.8/#files) and use `pip install (.whl file)`.

## Usage
While Encwork comes with demonstration files such as `client_example.py` and `server_example.py`, they are only meant to demonstrate how Encwork works. You can get the module to build your own UI that will work with any other program that uses Encwork, including the example one.

### The `client_example.py` and `server_example.py` files
As explained above, one machine will run the server (`server_example.py`) and allow clients to connect to it (`client_example.py`). The example files are for a server that returns ping, for one- and two-way, including encryption/decryption in the time.

# Documentation
To see how to use the Encwork module yourself, check out the [Documentation](https://github.com/Divarion-D/TCP-Model/wiki).