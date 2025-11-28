import asyncio
import socket
import struct
import json
import hashlib
import base64
import sys

# Constants
HEADER_HANDSHAKE = 0x01
HEADER_MESSAGE = 0x02
HEADER_SYSTEM = 0x03
TCP_PORT = 8000
WS_PORT = 8080
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

class ServerState:
    def __init__(self):
        self.ws_clients = set()  # Set of asyncio.StreamWriter
        self.tcp_clients = {}    # id -> asyncio.StreamWriter
        self.public_keys = {}    # id -> bytes (full packet)
        self.next_client_id = 0

    def add_tcp_client(self, writer):
        client_id = self.next_client_id
        self.next_client_id += 1
        self.tcp_clients[client_id] = writer
        return client_id

    def remove_tcp_client(self, client_id):
        if client_id in self.tcp_clients:
            del self.tcp_clients[client_id]
        # Also remove public key if exists
        if client_id in self.public_keys:
            del self.public_keys[client_id]

    def add_ws_client(self, writer):
        self.ws_clients.add(writer)

    def remove_ws_client(self, writer):
        self.ws_clients.discard(writer)

state = ServerState()

async def broadcast_ws(message_dict):
    """Send JSON message to all WebSocket clients"""
    if not state.ws_clients:
        return
    
    json_str = json.dumps(message_dict)
    frame = create_ws_frame(json_str)
    
    to_remove = set()
    for writer in state.ws_clients:
        try:
            writer.write(frame)
            await writer.drain()
        except Exception:
            to_remove.add(writer)
            
    for writer in to_remove:
        state.remove_ws_client(writer)

def create_ws_frame(message):
    """Create a WebSocket text frame (unmasked, for server->client)"""
    data = message.encode('utf-8')
    length = len(data)
    
    frame = bytearray()
    frame.append(0x81) # FIN + Text Opcode
    
    if length <= 125:
        frame.append(length)
    elif length <= 65535:
        frame.append(126)
        frame.extend(struct.pack('>H', length))
    else:
        frame.append(127)
        frame.extend(struct.pack('>Q', length))
        
    frame.extend(data)
    return frame

async def handle_tcp_client(reader, writer):
    # Allow more clients so the breaker can join (passive listener)
    if len(state.tcp_clients) >= 5:
        print(f"Rejected {writer.get_extra_info('peername')}: Server full")
        writer.close()
        await writer.wait_closed()
        return

    client_id = state.add_tcp_client(writer)
    addr = writer.get_extra_info('peername')
    client_name = f"C{client_id + 1}"
    
    print(f"TCP Client connected: {addr} (ID: {client_id})")
    
    # Broadcast connection event
    await broadcast_ws({
        "type": "EVENT",
        "message": f"Client {addr} connected"
    })

    try:
        while True:
            # Read Header (3 bytes)
            try:
                header = await reader.readexactly(3)
            except asyncio.IncompleteReadError:
                break # Client disconnected
                
            packet_type = header[0]
            length = struct.unpack('>H', header[1:3])[0]
            
            # Read Payload
            try:
                payload = await reader.readexactly(length)
            except asyncio.IncompleteReadError:
                break

            hex_payload = payload.hex().upper()
            
            # Reconstruct packet for forwarding
            packet = header + payload

            if packet_type == HEADER_HANDSHAKE:
                print(f" {client_name} sent public key ({length} bytes)")
                
                # Cache this public key
                state.public_keys[client_id] = packet
                
                # Send ALL OTHER cached keys to THIS client
                for other_id, other_packet in state.public_keys.items():
                    if other_id != client_id:
                        try:
                            writer.write(other_packet)
                            await writer.drain()
                        except Exception as e:
                            print(f"Error sending cached key to {client_name}: {e}")

                # Broadcast to WS
                await broadcast_ws({
                    "type": "PUBKEY",
                    "from": client_name,
                    "hex": hex_payload
                })

            elif packet_type == HEADER_MESSAGE:
                print(f" {client_name} sent encrypted message ({length} bytes)")
                
                # Broadcast to WS
                await broadcast_ws({
                    "type": "MSG",
                    "from": client_name,
                    "hex": hex_payload
                })
                
            else:
                print(f"Unknown packet type: {packet_type}")

            # Forward to ALL OTHER TCP clients
            for other_id, other_writer in state.tcp_clients.items():
                if other_id != client_id:
                    try:
                        other_writer.write(packet)
                        await other_writer.drain()
                    except Exception as e:
                        print(f"Error forwarding to C{other_id+1}: {e}")
                        # We could remove the client here, but we'll let its own handler deal with it

    except (ConnectionResetError, asyncio.IncompleteReadError):
        pass
    except Exception as e:
        print(f"Error handling client {client_id}: {e}")
    finally:
        print(f"Client {client_name} disconnected")
        state.remove_tcp_client(client_id)

        # Notify other TCP clients
        msg = f"Client {client_name} disconnected".encode('utf-8')
        header = struct.pack('>B H', HEADER_SYSTEM, len(msg))
        packet = header + msg
        
        for other_id, other_writer in state.tcp_clients.items():
            try:
                other_writer.write(packet)
                await other_writer.drain()
            except Exception:
                pass

        await broadcast_ws({
            "type": "EVENT",
            "message": f"Client {client_name} disconnected"
        })

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def handle_ws_client(reader, writer):
    addr = writer.get_extra_info('peername')
    print(f"WebSocket connection attempt from {addr}")
    
    try:
        # 1. Handshake
        # Read HTTP Request (simple parsing)
        request_data = await reader.readuntil(b'\r\n\r\n')
        request_str = request_data.decode('utf-8')
        
        # Extract Sec-WebSocket-Key
        key = None
        for line in request_str.split('\r\n'):
            if line.lower().startswith('sec-websocket-key:'):
                key = line.split(':')[1].strip()
                break
        
        if not key:
            print("Invalid WebSocket request: No key found")
            writer.close()
            return

        # Compute Accept
        accept_str = key + WS_GUID
        accept_sha1 = hashlib.sha1(accept_str.encode('utf-8')).digest()
        accept_b64 = base64.b64encode(accept_sha1).decode('utf-8')
        
        # Send Response
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept_b64}\r\n"
            "\r\n"
        )
        writer.write(response.encode('utf-8'))
        await writer.drain()
        
        print(f"WebSocket handshake successful with {addr}")
        state.add_ws_client(writer)
        
        # Keep connection open (we only send data, we don't really process incoming WS frames)
        # But we need to read to detect disconnection
        while True:
            # Just read and discard (or detect close)
            # A minimal frame is 2 bytes.
            try:
                _ = await reader.read(1024)
                if reader.at_eof():
                    break
            except Exception:
                break
                
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        print(f"WebSocket disconnected: {addr}")
        state.remove_ws_client(writer)
        writer.close()
        try:
            await writer.wait_closed()
        except:
            pass

async def main():
    # Start TCP Server
    tcp_server = await asyncio.start_server(
        handle_tcp_client, '127.0.0.1', TCP_PORT)
    
    print(f"TCP Server running on 127.0.0.1:{TCP_PORT}")

    # Start WebSocket Server
    ws_server = await asyncio.start_server(
        handle_ws_client, '127.0.0.1', WS_PORT)
        
    print(f"WebSocket Server running on 127.0.0.1:{WS_PORT}")

    async with tcp_server, ws_server:
        await asyncio.gather(
            tcp_server.serve_forever(),
            ws_server.serve_forever()
        )

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped.")
