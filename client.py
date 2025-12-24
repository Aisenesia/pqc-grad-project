import os
import socket
import threading
import sys
import struct
import secrets
import time
import argparse
from Crypto.Cipher import AES
from Crypto.Util import Counter
import lib

# Constants
HEADER_HANDSHAKE = 0x01
HEADER_MESSAGE = 0x02
HEADER_SYSTEM = 0x03
HEADER_KYBER_CAPSULE = 0x04
MODE_ECC = 0x01
MODE_KYBER = 0x02
PORT = 8000
HOST = '127.0.0.1'

# Global flag for headless mode
HEADLESS_MODE = False

class KeyManager:
    def __init__(self):
        self.shared_key = None
        self.lock = threading.Lock()
        self.mode = None
        self.kyber_sk = None  # Store Kyber secret key
        self.kyber_params = None
        self.kyber_pk = None  # Store our own public key
        self.has_encapsulated = False  # Track if we've sent a capsule

    def set_key(self, key):
        with self.lock:
            self.shared_key = key

    def get_key(self):
        with self.lock:
            return self.shared_key
    
    def set_mode(self, mode):
        with self.lock:
            self.mode = mode
    
    def get_mode(self):
        with self.lock:
            return self.mode
    
    def set_kyber_keys(self, pk, sk, params):
        with self.lock:
            self.kyber_pk = pk
            self.kyber_sk = sk
            self.kyber_params = params
    
    def get_kyber_keys(self):
        with self.lock:
            return self.kyber_pk, self.kyber_sk, self.kyber_params
    
    def set_encapsulated(self):
        with self.lock:
            self.has_encapsulated = True
    
    def has_sent_capsule(self):
        with self.lock:
            return self.has_encapsulated

def main():
    global HEADLESS_MODE
    
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Crypto Network Client')
    parser.add_argument('--mode', choices=['ECC', 'KYBER', '1', '2'], 
                        help='Cryptography mode: ECC/1 or KYBER/2')
    parser.add_argument('--headless', action='store_true',
                        help='Run in headless mode (no interactive input)')
    args = parser.parse_args()
    
    HEADLESS_MODE = args.headless
    
    # Select mode
    if args.mode:
        if args.mode in ['ECC', '1']:
            mode = MODE_ECC
        else:
            mode = MODE_KYBER
    else:
        print("Select cryptography mode:")
        print("1. ECC (Elliptic Curve Cryptography - secp256k1)")
        print("2. KYBER (Post-Quantum KEM - Kyber512)")
        
        while True:
            choice = input("Enter 1 or 2: ").strip()
            if choice == '1':
                mode = MODE_ECC
                break
            elif choice == '2':
                mode = MODE_KYBER
                break
            else:
                print("Invalid choice. Please enter 1 or 2.")
    
    # Connect to Server
    try:
        sock = socket.create_connection((HOST, PORT))
    except ConnectionRefusedError:
        if not HEADLESS_MODE:
            print("Failed to connect. Make sure the interceptor server is running!")
        sys.exit(1)
    
    # Initialize based on mode
    if mode == MODE_ECC:
        curve = lib.secp256k1()
        private_key = lib.generate_private_key(curve)
        public_key = lib.derive_public_key(curve, private_key)

        if not HEADLESS_MODE:
            print(f"\n=== ECC Mode ===")
            print(f"Private key: {hex(private_key)[2:]} (keep secret!)")
            print(f"Public key X: {hex(public_key.x)[2:]}")
            print(f"Public key Y: {hex(public_key.y)[2:]}")
        
        # Send ECC Public Key
        send_ecc_public_key(sock, public_key)
        crypto_data = (curve, private_key)
    
    else:  # MODE_KYBER
        params = lib.kyber512_params()
        public_key, secret_key = lib.kyber_keygen(params)
        
        if not HEADLESS_MODE:
            print(f"\n=== KYBER Mode ===")
            print(f"Public key: {len(public_key)} bytes")
            print(f"Secret key: {len(secret_key)} bytes")
        
        # Send Kyber Public Key
        send_kyber_public_key(sock, public_key)
        crypto_data = (params, secret_key)

    # Shared Key Manager
    key_manager = KeyManager()
    key_manager.set_mode(mode)
    
    if mode == MODE_KYBER:
        key_manager.set_kyber_keys(public_key, crypto_data[1], crypto_data[0])

    if not HEADLESS_MODE:
        print("\n(Messages are encrypted with AES-256-CTR)")
        print("Waiting for peer handshake...")

    # Start Receive Thread
    recv_thread = threading.Thread(
        target=receive_messages, 
        args=(sock, mode, crypto_data, key_manager), 
        daemon=True
    )
    recv_thread.start()

    # Send Loop
    if HEADLESS_MODE:
        # In headless mode, just keep the connection alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    else:
        send_messages(sock, key_manager)

def send_ecc_public_key(sock, public_key):
    x_bytes = public_key.x.to_bytes(32, 'big')
    y_bytes = public_key.y.to_bytes(32, 'big')
    payload = bytes([MODE_ECC]) + x_bytes + y_bytes
    
    # Header: Type (1) + Length (2)
    header = struct.pack('>B H', HEADER_HANDSHAKE, len(payload))
    sock.sendall(header + payload)

def send_kyber_public_key(sock, public_key):
    payload = bytes([MODE_KYBER]) + public_key
    
    # Header: Type (1) + Length (2)
    header = struct.pack('>B H', HEADER_HANDSHAKE, len(payload))
    sock.sendall(header + payload)

def send_messages(sock, key_manager):
    while key_manager.get_key() is None:
        time.sleep(0.1)

    if not HEADLESS_MODE:
        print("Type a message and press Enter:")
    
    while True:
        try:
            if HEADLESS_MODE:
                # In headless mode, don't try to read from stdin
                time.sleep(1)
                continue
            
            line = input()
        except (EOFError, KeyboardInterrupt):
            if not HEADLESS_MODE:
                print("\nExiting...")
            break
            
        if not line:
            continue
            
        shared_key = key_manager.get_key()
        if shared_key is None:
            if not HEADLESS_MODE:
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
            if not HEADLESS_MODE:
                print("Socket closed.")
            break

def receive_messages(sock, mode, crypto_data, key_manager):
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
                    print(f"\n[System] {payload.decode('utf-8')}", flush=True)
                except:
                    pass
                continue

            if packet_type == HEADER_HANDSHAKE:
                # First byte is mode
                if len(payload) < 1:
                    print("\nInvalid handshake payload")
                    continue
                
                peer_mode = payload[0]
                peer_pubkey = payload[1:]
                
                # Handle ECC handshake
                if mode == MODE_ECC and peer_mode == MODE_ECC:
                    if len(peer_pubkey) != 64:
                        print("\nInvalid ECC public key length")
                        continue
                    
                    curve, private_key = crypto_data
                    x_bytes = peer_pubkey[:32]
                    y_bytes = peer_pubkey[32:]
                    x = int.from_bytes(x_bytes, 'big')
                    y = int.from_bytes(y_bytes, 'big')
                    peer_public = lib.Point.new(x, y)
                    
                    # Derive Shared Secret
                    shared_point = lib.derive_shared_secret(curve, private_key, peer_public)
                    shared_key = lib.point_to_shared_key(shared_point)
                    
                    key_manager.set_key(shared_key)
                    if not HEADLESS_MODE:
                        print(f"\n[ECC Key Update] Handshake received from ECC peer.", flush=True)
                        print(f"Shared point X: {hex(shared_point.x)[2:]}", flush=True)
                        print(f"Symmetric key: {shared_key.hex()}", flush=True)
                
                # Handle Kyber handshake
                elif mode == MODE_KYBER and peer_mode == MODE_KYBER:
                    our_pk, our_sk, params = key_manager.get_kyber_keys()
                    
                    # Determine who encapsulates: compare public keys lexicographically
                    # The client with the "smaller" public key encapsulates
                    should_encapsulate = our_pk < peer_pubkey
                    
                    if should_encapsulate and not key_manager.has_sent_capsule():
                        # We encapsulate using peer's public key
                        shared_secret, ciphertext = lib.kyber_encapsulate(peer_pubkey, params)
                        
                        key_manager.set_key(shared_secret)
                        key_manager.set_encapsulated()
                        if not HEADLESS_MODE:
                            print(f"\n[KYBER Key Update] Encapsulated with peer's public key.", flush=True)
                            print(f"Shared secret: {shared_secret.hex()}", flush=True)
                        
                        # Send capsule back
                        capsule_payload = ciphertext
                        capsule_header = struct.pack('>B H', HEADER_KYBER_CAPSULE, len(capsule_payload))
                        sock.sendall(capsule_header + capsule_payload)
                    else:
                        # We wait for the capsule from peer
                        if not HEADLESS_MODE:
                            print(f"\n[KYBER] Received peer's public key. Waiting for capsule...", flush=True)
                
                else:
                    if not HEADLESS_MODE:
                        print(f"\n[Warning] Mode mismatch: You are in {'ECC' if mode == MODE_ECC else 'KYBER'} mode, peer is in {'ECC' if peer_mode == MODE_ECC else 'KYBER'} mode.", flush=True)
                
                continue
            
            if packet_type == HEADER_KYBER_CAPSULE:
                # Decapsulate the ciphertext
                if mode != MODE_KYBER:
                    if not HEADLESS_MODE:
                        print("\n[Warning] Received Kyber capsule but not in Kyber mode")
                    continue
                
                our_pk, our_sk, params = key_manager.get_kyber_keys()
                shared_secret = lib.kyber_decapsulate(payload, our_sk, params)
                
                key_manager.set_key(shared_secret)
                if not HEADLESS_MODE:
                    print(f"\n[KYBER Key Update] Decapsulated ciphertext.", flush=True)
                    print(f"Shared secret: {shared_secret.hex()}", flush=True)
                continue

            if packet_type == HEADER_MESSAGE:
                shared_key = key_manager.get_key()
                if shared_key is None:
                    if not HEADLESS_MODE:
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
                    if not HEADLESS_MODE:
                        print(f"Received: {plaintext.decode('utf-8')}", flush=True)
                except UnicodeDecodeError:
                    if not HEADLESS_MODE:
                        print("Received invalid UTF-8 message", flush=True)
                
        except (OSError, struct.error):
            if not HEADLESS_MODE:
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
