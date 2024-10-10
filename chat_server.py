import socket
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

p = 23
g = 5

def generate_private_key():
    return bytes_to_long(get_random_bytes(16))

def generate_public_key(private_key):
    return pow(g, private_key, p)

def generate_shared_secret(their_public_key, private_key):
    return pow(their_public_key, private_key, p)

def derive_key(shared_secret):
    salt = get_random_bytes(16)
    key = PBKDF2(str(shared_secret), salt, dkLen=32)
    return key, salt

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return cipher.nonce, ciphertext, tag

def decrypt_message(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')

# Helper function to receive a fixed amount of bytes
def recv_fixed(conn, length):
    data = b''
    while len(data) < length:
        packet = conn.recv(length - len(data))
        if not packet:
            break
        data += packet
    return data

# Setup server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 5555))
server_socket.listen(1)
print("Server is waiting for a connection...")

conn, addr = server_socket.accept()
print(f"Connected by {addr}")

# Diffie-Hellman key exchange
server_private_key = generate_private_key()
server_public_key = generate_public_key(server_private_key)

# Send public key to client
conn.sendall(long_to_bytes(server_public_key))

# Receive public key from client
client_public_key = bytes_to_long(conn.recv(1024))

# Generate shared secret
shared_secret = generate_shared_secret(client_public_key, server_private_key)
print(f"Shared secret established: {shared_secret}")

# Derive encryption key
aes_key, salt = derive_key(shared_secret)

# Chat loop
while True:
    try:
        # Receive encrypted message from client
        nonce = recv_fixed(conn, 16)  # Nonce should be 16 bytes
        ciphertext_len = int.from_bytes(recv_fixed(conn, 4), 'big')
        ciphertext = recv_fixed(conn, ciphertext_len)
        tag = recv_fixed(conn, 16)  # Tag should be 16 bytes

        print(f"Received nonce: {nonce}")
        print(f"Received ciphertext: {ciphertext}")
        print(f"Received tag: {tag}")

        # Decrypt message
        decrypted_message = decrypt_message(nonce, ciphertext, tag, aes_key)
        print(f"Client: {decrypted_message}")
        
        # Send encrypted response
        response = input("You: ")
        nonce, ciphertext, tag = encrypt_message(response, aes_key)
        conn.sendall(nonce)
        conn.sendall(len(ciphertext).to_bytes(4, 'big'))
        conn.sendall(ciphertext)
        conn.sendall(tag)
        print(f"Sent nonce: {nonce}")
        print(f"Sent ciphertext: {ciphertext}")
        print(f"Sent tag: {tag}")

    except ValueError as e:
        print(f"Decryption failed: {e}")
    except KeyboardInterrupt:
        print("\nServer shutting down...")
        break
