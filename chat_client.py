import socket
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# Parameters for Diffie-Hellman (prime and base)
p = 23  # Use a larger prime in real-world scenarios
g = 5   # Base

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
def recv_fixed(sock, length):
    data = b''
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            break
        data += packet
    return data

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 5555))

# Diffie-Hellman key exchange
client_private_key = generate_private_key()
client_public_key = generate_public_key(client_private_key)

# Receive public key from server
server_public_key = bytes_to_long(client_socket.recv(1024))

# Send public key to server
client_socket.sendall(long_to_bytes(client_public_key))

# Generate shared secret
shared_secret = generate_shared_secret(server_public_key, client_private_key)
print(f"Shared secret established: {shared_secret}")

# Derive encryption key
aes_key, salt = derive_key(shared_secret)

while True:
    try:
        message = input("You: ")
        nonce, ciphertext, tag = encrypt_message(message, aes_key)
        client_socket.sendall(nonce)
        client_socket.sendall(len(ciphertext).to_bytes(4, 'big'))
        client_socket.sendall(ciphertext)
        client_socket.sendall(tag)
        print(f"Sent nonce: {nonce}")
        print(f"Sent ciphertext: {ciphertext}")
        print(f"Sent tag: {tag}")

        nonce = recv_fixed(client_socket, 16)
        ciphertext_len = int.from_bytes(recv_fixed(client_socket, 4), 'big')
        ciphertext = recv_fixed(client_socket, ciphertext_len)
        tag = recv_fixed(client_socket, 16)
        print(f"Received nonce: {nonce}")
        print(f"Received ciphertext: {ciphertext}")
        print(f"Received tag: {tag}")

        decrypted_message = decrypt_message(nonce, ciphertext, tag, aes_key)
        print(f"Server: {decrypted_message}")

    except ValueError as e:
        print(f"Decryption failed: {e}")
    except KeyboardInterrupt:
        print("\nClient shutting down...")
        break
