# Encrypted Chat Application

## Overview

This project is an encrypted chat application where a server and a client can securely exchange messages over a network. The application uses **AES encryption** to secure messages, with encryption keys derived using **Diffie-Hellman key exchange**. This ensures that the communication between the server and client is encrypted and protected from unauthorized access.

## Features

- **End-to-End Encryption**: Messages between the server and client are encrypted using AES (Advanced Encryption Standard).
- **Diffie-Hellman Key Exchange**: Encryption keys are securely exchanged using the Diffie-Hellman algorithm.
- **Secure Message Transmission**: The application ensures that messages are transmitted securely with encryption and integrity checks (AES with EAX mode).

## Components

- **`chat_server.py`**: The server-side script that listens for client connections, performs the key exchange, and enables encrypted communication.
- **`chat_client.py`**: The client-side script that connects to the server and initiates encrypted communication.

## Prerequisites

- **Python 3.x**
- **Required Libraries**:
  - `pycryptodome` (for cryptographic operations)

Install the `pycryptodome` library if it's not already installed:

```bash
pip install pycryptodome
