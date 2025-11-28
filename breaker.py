import socket
import struct
import sys
import os
import time
import threading
import lib

# Constants
HEADER_HANDSHAKE = 0x01
HEADER_MESSAGE = 0x02
HEADER_SYSTEM = 0x03
PORT = 8000
HOST = '127.0.0.1'

def main():
    print("--- ECC INTERCEPTOR / CODE BREAKER ---")
    print("Targeting: 127.0.0.1:8000")
    
    # Initialize Curve
    curve = lib.secp256k1()
    
    try:
        sock = socket.create_connection((HOST, PORT))
    except ConnectionRefusedError:
        print("Target server not found.")
        return

    print("Connected. Listening for encrypted traffic...")
    
    while True:
        try:
            header_data = recv_exact(sock, 3)
            if not header_data:
                print("Target disconnected.")
                break
                
            packet_type, length = struct.unpack('>B H', header_data)
            payload = recv_exact(sock, length)
            
            if packet_type == HEADER_HANDSHAKE:
                if len(payload) != 64: continue
                
                x = int.from_bytes(payload[:32], 'big')
                y = int.from_bytes(payload[32:], 'big')
                target_pub = lib.Point.new(x, y)
                
                print(f"\n[INTERCEPTED] Public Key Exchange")
                print(f"  > Target Public Key X: {hex(x)[:10]}...")
                
                # Start cracking in background
                t = threading.Thread(target=crack_ecdlp, args=(curve, target_pub))
                t.daemon = True
                t.start()
                
            elif packet_type == HEADER_MESSAGE:
                print(f"\n[INTERCEPTED] Encrypted Message ({length} bytes)")
                print("  > Cannot decrypt: Shared secret unknown.")
                print("  > Waiting for Private Key Cracker to finish (ETA: Billions of years)...")
                
            elif packet_type == HEADER_SYSTEM:
                print(f"\n[SYSTEM] {payload.decode('utf-8', errors='ignore')}")

        except Exception as e:
            print(f"Error: {e}")
            break

def crack_ecdlp(curve, target_pub):
    print(f"  > [CRACKER] Initiating ECDLP Attack on key {hex(target_pub.x)[:10]}...")
    print("  > [CRACKER] Method: Brute Force (Baby-step)")
    print("  > [CRACKER] Goal: Find k where k * G = Public_Key")
    
    # Start from 1
    current_point = curve.generator
    k = 1
    start_time = time.time()
    
    while True:
        if current_point == target_pub:
            print(f"\n  > [CRACKER] !!! IMPOSSIBLE !!! Private Key Found: {k}")
            break
            
        # Next point
        current_point = curve.add(current_point, curve.generator)
        k += 1
        
        # Show stats every 10,000 keys
        if k % 10000 == 0:
            elapsed = time.time() - start_time
            if elapsed > 0:
                rate = k / elapsed
                
                # Calculate ETA
                total_keys = curve.order
                remaining = total_keys - k
                seconds_needed = remaining / rate
                years = seconds_needed / (3600 * 24 * 365)
                
                print(f"  > [CRACKER] Checked {k} keys... Last tried: k={k} | X={hex(current_point.x)[:10]}... | Match: NO")
                print(f"  > [CRACKER] ... Speed: {rate:.0f} keys/sec | ETA: {years:.2e} YEARS")

def recv_exact(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting...")
