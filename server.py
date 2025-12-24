import asyncio
import socket
import struct
import json
import hashlib
import base64
import sys
import os
import subprocess
from pathlib import Path

# Constants
HEADER_HANDSHAKE = 0x01
HEADER_MESSAGE = 0x02
HEADER_SYSTEM = 0x03
HEADER_KYBER_CAPSULE = 0x04
MODE_ECC = 0x01
MODE_KYBER = 0x02
TCP_PORT = 8000
WS_PORT = 8080
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

class ServerState:
    def __init__(self):
        self.ws_clients = set()  # Set of asyncio.StreamWriter
        self.tcp_clients = {}    # id -> asyncio.StreamWriter
        self.public_keys = {}    # id -> bytes (full packet)
        self.client_modes = {}   # id -> MODE_ECC or MODE_KYBER
        self.next_client_id = 0
        self.client_processes = {}  # process_id -> {'process': Popen, 'mode': str, 'name': str}
        self.next_process_id = 0

    def add_tcp_client(self, writer):
        client_id = self.next_client_id
        self.next_client_id += 1
        self.tcp_clients[client_id] = writer
        return client_id

    def remove_tcp_client(self, client_id):
        if client_id in self.tcp_clients:
            del self.tcp_clients[client_id]
        # Also remove public key and mode if exists
        if client_id in self.public_keys:
            del self.public_keys[client_id]
        if client_id in self.client_modes:
            del self.client_modes[client_id]

    def set_client_mode(self, client_id, mode):
        self.client_modes[client_id] = mode
    
    def get_client_mode(self, client_id):
        return self.client_modes.get(client_id, None)

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
                # First byte of payload is the mode
                if length < 1:
                    print(f" {client_name} sent invalid handshake")
                    continue
                
                mode = payload[0]
                mode_str = "ECC" if mode == MODE_ECC else "KYBER" if mode == MODE_KYBER else "UNKNOWN"
                
                # Store the client mode
                state.set_client_mode(client_id, mode)
                
                print(f" {client_name} sent {mode_str} public key ({length} bytes)")
                
                # Cache this public key
                state.public_keys[client_id] = packet
                
                # Send ALL OTHER cached keys to THIS client (only same mode)
                for other_id, other_packet in state.public_keys.items():
                    if other_id != client_id:
                        other_mode = state.get_client_mode(other_id)
                        # Only forward if same mode
                        if other_mode == mode:
                            try:
                                writer.write(other_packet)
                                await writer.drain()
                            except Exception as e:
                                print(f"Error sending cached key to {client_name}: {e}")

                # Broadcast to WS
                await broadcast_ws({
                    "type": "PUBKEY",
                    "from": client_name,
                    "mode": mode_str,
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
                
            elif packet_type == HEADER_KYBER_CAPSULE:
                print(f" {client_name} sent Kyber capsule ({length} bytes)")
                
                # Broadcast to WS
                await broadcast_ws({
                    "type": "KYBER_CAPSULE",
                    "from": client_name,
                    "hex": hex_payload
                })
                
            else:
                print(f"Unknown packet type: {packet_type}")

            # Forward to ALL OTHER TCP clients (regardless of mode for messages/capsules)
            # This allows mixed networks where some use ECC and some use Kyber
            for other_id, other_writer in state.tcp_clients.items():
                if other_id != client_id:
                    try:
                        other_writer.write(packet)
                        await other_writer.drain()
                    except Exception as e:
                        print(f"Error forwarding to C{other_id+1}: {e}")

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
        
        # Check if this is an HTTP control request
        if request_str.startswith('POST /start-client'):
            await handle_http_start_client(request_str, reader, writer)
            return
        
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
                data = await reader.read(1024)
                if reader.at_eof():
                    break
                # Handle incoming WebSocket control commands
                if data:
                    await handle_ws_message(data, writer)
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

async def handle_ws_message(data, writer):
    """Handle incoming WebSocket messages for control commands"""
    try:
        # Skip WebSocket frame header (basic parsing)
        if len(data) < 2:
            return
        
        # Check if it's a text frame (opcode 0x1)
        opcode = data[0] & 0x0F
        if opcode != 0x1:
            return
        
        # Get payload length and mask
        masked = (data[1] & 0x80) != 0
        payload_len = data[1] & 0x7F
        
        offset = 2
        if payload_len == 126:
            payload_len = int.from_bytes(data[2:4], 'big')
            offset = 4
        elif payload_len == 127:
            payload_len = int.from_bytes(data[2:10], 'big')
            offset = 10
        
        if masked:
            mask = data[offset:offset+4]
            offset += 4
            payload = bytearray(data[offset:offset+payload_len])
            for i in range(len(payload)):
                payload[i] ^= mask[i % 4]
            message = payload.decode('utf-8')
        else:
            message = data[offset:offset+payload_len].decode('utf-8')
        
        # Parse JSON command
        cmd = json.loads(message)
        
        if cmd.get('command') == 'start_client':
            mode = cmd.get('mode', 'ECC')
            await start_client_process(mode)
        elif cmd.get('command') == 'send_to_client':
            process_id = cmd.get('processId')
            msg = cmd.get('message', '')
            
            if process_id in state.client_processes:
                client_info = state.client_processes[process_id]
                process = client_info['process']
                
                # Write to client's stdin
                try:
                    process.stdin.write((msg + '\n').encode('utf-8'))
                    process.stdin.flush()
                except Exception as e:
                    print(f"Error writing to client stdin: {e}")
            
    except Exception as e:
        print(f"Error handling WS message: {e}")

async def handle_http_start_client(request_str, reader, writer):
    """Handle HTTP POST request to start a client"""
    try:
        # Read body if present
        content_length = 0
        for line in request_str.split('\r\n'):
            if line.lower().startswith('content-length:'):
                content_length = int(line.split(':')[1].strip())
        
        body = b''
        if content_length > 0:
            body = await reader.read(content_length)
        
        # Parse mode from body
        mode = 'ECC'
        if body:
            try:
                data = json.loads(body.decode('utf-8'))
                mode = data.get('mode', 'ECC')
            except:
                pass
        
        # Start client
        await start_client_process(mode)
        
        # Send response
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "\r\n"
            '{"status": "ok", "message": "Client started"}'
        )
        writer.write(response.encode('utf-8'))
        await writer.drain()
        
    except Exception as e:
        print(f"Error starting client: {e}")
        response = (
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            f'{{"status": "error", "message": "{str(e)}"}}'
        )
        writer.write(response.encode('utf-8'))
        await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()

async def read_client_output(process_id, process):
    """Read stdout from client process and broadcast to WebSocket"""
    try:
        loop = asyncio.get_event_loop()
        while True:
            # Read line from stdout (blocking, so run in executor)
            line = await loop.run_in_executor(None, process.stdout.readline)
            if not line:
                break  # Process ended
            
            text = line.decode('utf-8', errors='ignore').rstrip()
            if text:
                # Broadcast to WebSocket
                await broadcast_ws({
                    "type": "CLIENT_OUTPUT",
                    "processId": process_id,
                    "output": text
                })
    except Exception as e:
        print(f"Error reading client output: {e}")
    finally:
        # Process ended
        if process_id in state.client_processes:
            client_info = state.client_processes[process_id]
            await broadcast_ws({
                "type": "CLIENT_ENDED",
                "processId": process_id,
                "name": client_info['name']
            })
            del state.client_processes[process_id]

async def start_client_process(mode):
    """Start a client process with the given mode (ECC or KYBER)"""
    try:
        client_script = Path(__file__).parent / 'client.py'
        
        # Windows-specific flag to prevent window creation
        if sys.platform == 'win32':
            CREATE_NO_WINDOW = 0x08000000
        else:
            CREATE_NO_WINDOW = 0
        
        # Set up environment with unbuffered Python output
        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'
        
        # Start client with PIPE for stdin/stdout (not headless anymore, but no window)
        process = subprocess.Popen(
            [sys.executable, '-u', str(client_script), '--mode', mode],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Merge stderr into stdout
            creationflags=CREATE_NO_WINDOW if sys.platform == 'win32' else 0,
            bufsize=1,  # Line buffered
            env=env
        )
        
        process_id = state.next_process_id
        state.next_process_id += 1
        client_name = f"C{process_id + 1}"
        
        state.client_processes[process_id] = {
            'process': process,
            'mode': mode,
            'name': client_name,
            'pid': process.pid
        }
        
        # Start async task to read stdout and broadcast to WebSocket
        asyncio.create_task(read_client_output(process_id, process))
        
        print(f"Started {mode} client process {client_name} (PID: {process.pid})")
        
        # Broadcast to WebSocket clients
        await broadcast_ws({
            "type": "EVENT",
            "message": f"Started {mode} client {client_name} (PID: {process.pid})"
        })
        
    except Exception as e:
        print(f"Failed to start client: {e}")
        await broadcast_ws({
            "type": "EVENT",
            "message": f"Error starting client: {str(e)}"
        })

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
