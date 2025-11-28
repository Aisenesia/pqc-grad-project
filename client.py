import os
import socket
import threading
import sys
import struct
import secrets
import time
from Crypto.Cipher import AES
from Crypto.Util import Counter
import lib

# Constants
HEADER_HANDSHAKE = 0x01
HEADER_MESSAGE = 0x02
HEADER_SYSTEM = 0x03
PORT = 8000
HOST = '127.0.0.1'

class KeyManager:
    def __init__(self):
        self.shared_key = None
        self.lock = threading.Lock()

    def set_key(self, key):
        with self.lock:
            self.shared_key = key

    def get_key(self):
        with self.lock:
            return self.shared_key

def main():
    # 1. Initialize Curve and Keys
    curve = lib.secp256k1()
    private_key = lib.generate_private_key(curve)
    public_key = lib.derive_public_key(curve, private_key)

    print(f"Private key: {hex(private_key)[2:]} (keep secret!)")
    print(f"Public key X: {hex(public_key.x)[2:]}")
    print(f"Public key Y: {hex(public_key.y)[2:]}")

    # 2. Connect to Server
    try:
        sock = socket.create_connection((HOST, PORT))
    except ConnectionRefusedError:
        print("Failed to connect. Make sure the interceptor server is running!")
        return

    # 3. Send Public Key
    send_public_key(sock, public_key)

    # 4. Shared Key Manager
    key_manager = KeyManager()

    print("(Messages are encrypted with AES-256-CTR)")
    print("Waiting for peer handshake...")

    # 5. Start Receive Thread
    # We pass curve and private_key to allow derivation in the thread
    recv_thread = threading.Thread(
        target=receive_messages, 
        args=(sock, curve, private_key, key_manager), 
        daemon=True
    )
    recv_thread.start()

    # 6. Send Loop
    send_messages(sock, key_manager)

def send_public_key(sock, public_key):
    x_bytes = public_key.x.to_bytes(32, 'big')
    y_bytes = public_key.y.to_bytes(32, 'big')
    payload = x_bytes + y_bytes
    
    # Header: Type (1) + Length (2)
    header = struct.pack('>B H', HEADER_HANDSHAKE, len(payload))
    sock.sendall(header + payload)

def send_messages(sock, key_manager):
    while key_manager.get_key() is None:
        time.sleep(0.1)

    print("Type a message and press Enter:")
    while True:
        try:
            line = input()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting...")
            break
            
        if not line:
            continue
            
        shared_key = key_manager.get_key()
        if shared_key is None:
            print("No peer connected. Cannot send encrypted message.")
            continue

        plaintext = line.encode('utf-8')
        iv = secrets.token_bytes(16)
        
        # AES-CTR
        ctr = Counter.new(128, initial_value=int.from_bytes(iv, 'big'))
        cipher = AES.new(shared_key, AES.MODE_CTR, counter=ctr)
        ciphertext = cipher.encrypt(plaintext)
        
        payload = iv + ciphertext
        header = struct.pack('>B H', HEADER_MESSAGE, len(payload))
        
        try:
            sock.sendall(header + payload)
        except OSError:
            print("Socket closed.")
            break

def receive_messages(sock, curve, private_key, key_manager):
    while True:
        try:
            header_data = recv_exact(sock, 3)
            if not header_data:
                print("\nServer disconnected.")
                os._exit(0)
                
            packet_type, length = struct.unpack('>B H', header_data)
            payload = recv_exact(sock, length)
            
            if packet_type == HEADER_SYSTEM:
                try:
                    print(f"\n[System] {payload.decode('utf-8')}")
                except:
                    pass
                continue

            if packet_type == HEADER_HANDSHAKE:
                # Parse Peer Public Key
                if len(payload) != 64:
                    print("\nInvalid handshake payload length")
                    continue
                    
                x_bytes = payload[:32]
                y_bytes = payload[32:]
                x = int.from_bytes(x_bytes, 'big')
                y = int.from_bytes(y_bytes, 'big')
                peer_public = lib.Point.new(x, y)
                
                # Derive Shared Secret
                shared_point = lib.derive_shared_secret(curve, private_key, peer_public)
                shared_key = lib.point_to_shared_key(shared_point)
                
                key_manager.set_key(shared_key)
                print(f"\n[Key Update] Handshake received.")
                print(f"Shared point X: {hex(shared_point.x)[2:]}")
                print(f"Symmetric key: {shared_key.hex()}")
                continue

            if packet_type == HEADER_MESSAGE:
                shared_key = key_manager.get_key()
                if shared_key is None:
                    print("\nReceived message but no key established.")
                    continue

                if len(payload) < 16:
                    continue
                    
                iv = payload[:16]
                ciphertext = payload[16:]
                
                ctr = Counter.new(128, initial_value=int.from_bytes(iv, 'big'))
                cipher = AES.new(shared_key, AES.MODE_CTR, counter=ctr)
                plaintext = cipher.decrypt(ciphertext)
                
                try:
                    print(f"Received: {plaintext.decode('utf-8')}")
                except UnicodeDecodeError:
                    print("Received invalid UTF-8 message")
                
        except (OSError, struct.error):
            print("\nConnection lost.")
            os._exit(0)

def recv_exact(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise OSError("Connection closed")
        data += packet
    return data

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
